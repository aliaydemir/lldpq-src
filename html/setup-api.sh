#!/bin/bash
# setup-api.sh - SSH Setup API (send-key + sudo-fix)
# Backend for SSH Setup modal in assets.html
# Called by nginx fcgiwrap

# Admin-only guard (validates session, exits 401/403 if not admin)
source "$(dirname "$0")/auth-guard.sh"
require_admin

# Load allowlisted config data through the fixed, root-owned parser. A missing
# helper is a broken/partial installation; silently using Docker-style defaults
# could make Setup operate on the wrong installation tree.
if [[ ! -x /usr/local/bin/lldpq-config ]]; then
    echo "Content-Type: application/json"
    echo ""
    echo '{"success": false, "error": "Required runtime config helper is missing; run install.sh to repair this installation."}'
    exit 0
fi
if ! LLDPQ_CONFIG_ASSIGNMENTS=$(/usr/local/bin/lldpq-config --require-config \
    --require-key LLDPQ_DIR --require-key LLDPQ_USER --require-key WEB_ROOT \
    2>/dev/null); then
    echo "Content-Type: application/json"
    echo ""
    echo '{"success": false, "error": "Runtime configuration is missing or unreadable; run install.sh to repair this installation."}'
    exit 0
fi
eval "$LLDPQ_CONFIG_ASSIGNMENTS"

LLDPQ_DIR="${LLDPQ_DIR:-/home/lldpq/lldpq}"
LLDPQ_USER="${LLDPQ_USER:-lldpq}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"
LLDPQ_PROVISION_STATE_DIR="${LLDPQ_PROVISION_STATE_DIR:-/var/lib/lldpq/provision-state}"
LLDPQ_DIRECT_WRITE_STATE_DIR="${LLDPQ_DIRECT_WRITE_STATE_DIR:-$LLDPQ_PROVISION_STATE_DIR/config-write-journals}"
SETUP_SAFETY="$(dirname "$0")/setup_safety.py"

# ─── Fast path: raw tarball upload (Setup → Update → Offline). The request body IS the file
# (application/octet-stream), so stream stdin straight to disk in big chunks. The generic
# byte-wise JSON reader below would be far too slow and would corrupt binary data. The
# destination is a unique server-created /tmp file; the action comes via the query string.
# Retire abandoned uploads from interrupted browser sessions without touching
# arbitrary /tmp files or a package currently moving through a normal update.
find /tmp -maxdepth 1 -type f -uid "$(id -u)" \
    -name 'lldpq-upload-src.*.tar.gz' -mmin +1440 -delete 2>/dev/null || true
case "$QUERY_STRING" in
  *action=upload-src*)
    echo "Content-Type: application/json"
    echo "Cache-Control: no-store"
    echo "X-Content-Type-Options: nosniff"
    echo ""
    if [ "$REQUEST_METHOD" != "POST" ]; then echo '{"success": false, "error": "POST required"}'; exit 0; fi
    umask 027
    UP_DEST=$(mktemp /tmp/lldpq-upload-src.XXXXXX.tar.gz) || {
        echo '{"success": false, "error": "Could not create a private upload buffer"}'
        exit 0
    }
    MAX_UPLOAD_BYTES=536870912
    if [ -n "$CONTENT_LENGTH" ]; then
        if ! [[ "$CONTENT_LENGTH" =~ ^[0-9]+$ ]] || [ "${#CONTENT_LENGTH}" -gt 12 ]; then
            rm -f "$UP_DEST" 2>/dev/null
            echo '{"success": false, "error": "Invalid Content-Length"}'
            exit 0
        fi
        UP_LENGTH=$((10#$CONTENT_LENGTH))
        if [ "$UP_LENGTH" -le 0 ] || [ "$UP_LENGTH" -gt "$MAX_UPLOAD_BYTES" ]; then
            rm -f "$UP_DEST" 2>/dev/null
            echo '{"success": false, "error": "Offline source upload must be between 1 byte and 512 MiB"}'
            exit 0
        fi
        head -c "$UP_LENGTH" > "$UP_DEST" 2>/dev/null
        UP_READ=$(wc -c < "$UP_DEST" 2>/dev/null | tr -d ' ')
        if [ "${UP_READ:-0}" -ne "$UP_LENGTH" ]; then
            rm -f "$UP_DEST" 2>/dev/null
            echo '{"success": false, "error": "Offline source upload was truncated"}'
            exit 0
        fi
    else
        head -c $((MAX_UPLOAD_BYTES + 1)) > "$UP_DEST" 2>/dev/null
    fi
    chgrp www-data "$UP_DEST" 2>/dev/null || true
    chmod 640 "$UP_DEST" 2>/dev/null
    UP_SZ=$(wc -c < "$UP_DEST" 2>/dev/null | tr -d ' ')
    UP_MAGIC=$(od -An -tx1 -N2 "$UP_DEST" 2>/dev/null | tr -d ' \n')
    if [ "${UP_SZ:-0}" -gt "$MAX_UPLOAD_BYTES" ] 2>/dev/null; then
        rm -f "$UP_DEST" 2>/dev/null
        echo '{"success": false, "error": "Offline source upload exceeds 512 MiB"}'
    elif [ "${UP_SZ:-0}" -gt 0 ] 2>/dev/null && [ "$UP_MAGIC" = "1f8b" ]; then
        echo "{\"success\": true, \"path\": \"$UP_DEST\", \"size\": ${UP_SZ}}"
    else
        rm -f "$UP_DEST" 2>/dev/null
        echo "{\"success\": false, \"error\": \"Upload is not a valid .tar.gz (gzip) file.\"}"
    fi
    exit 0
    ;;
esac

# Output JSON header
echo "Content-Type: application/json"
echo "Cache-Control: no-store"
echo "X-Content-Type-Options: nosniff"
echo ""

# Only accept POST
if [ "$REQUEST_METHOD" != "POST" ]; then
    echo '{"success": false, "error": "POST method required"}'
    exit 0
fi

# Spool JSON privately instead of exporting it.  Environment export hits ARG_MAX
# for backup bundles and exposes passwords/keys through the process environment.
umask 077
POST_DATA_FILE=$(mktemp /tmp/lldpq-setup-request.XXXXXX) || {
    echo '{"success": false, "error": "Could not create a private request buffer"}'
    exit 0
}
trap 'rm -f "$POST_DATA_FILE"' EXIT
MAX_JSON_BYTES=33554432
if [ -n "$CONTENT_LENGTH" ]; then
    if ! [[ "$CONTENT_LENGTH" =~ ^[0-9]+$ ]] || [ "${#CONTENT_LENGTH}" -gt 10 ]; then
        echo '{"success": false, "error": "Invalid Content-Length"}'
        exit 0
    fi
    CONTENT_LENGTH_NUM=$((10#$CONTENT_LENGTH))
    if [ "$CONTENT_LENGTH_NUM" -gt "$MAX_JSON_BYTES" ]; then
        echo '{"success": false, "error": "JSON request exceeds the 32 MiB limit"}'
        exit 0
    fi
    head -c "$CONTENT_LENGTH_NUM" > "$POST_DATA_FILE" 2>/dev/null
    READ_SIZE=$(wc -c < "$POST_DATA_FILE" 2>/dev/null | tr -d ' ')
    if [ "${READ_SIZE:-0}" -ne "$CONTENT_LENGTH_NUM" ]; then
        echo '{"success": false, "error": "JSON request body was truncated"}'
        exit 0
    fi
else
    head -c $((MAX_JSON_BYTES + 1)) > "$POST_DATA_FILE" 2>/dev/null
    READ_SIZE=$(wc -c < "$POST_DATA_FILE" 2>/dev/null | tr -d ' ')
    if [ "${READ_SIZE:-0}" -gt "$MAX_JSON_BYTES" ]; then
        echo '{"success": false, "error": "JSON request exceeds the 32 MiB limit"}'
        exit 0
    fi
fi

# Export for Python
export LLDPQ_DIR LLDPQ_USER WEB_ROOT LLDPQ_PROVISION_STATE_DIR
export LLDPQ_DIRECT_WRITE_STATE_DIR POST_DATA_FILE SETUP_SAFETY

python3 << 'PYTHON'
import json
import sys
import os
import subprocess
import re
import shlex
import fcntl
import stat
import tempfile
import hashlib
import importlib.util
import time
import uuid
import grp
import pwd
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed

CRON_VALIDATOR = '/usr/local/bin/lldpq-config'
BACKUP_IMPORT_HELPER = '/usr/local/libexec/lldpq-backup-import.py'
UNINSTALL_WEB_HELPER = '/usr/local/libexec/lldpq-uninstall-web.py'
LIFECYCLE_LOCK_FILE = '/etc/lldpq.lifecycle.lock'
UNINSTALL_ACTIVE_MARKER = '/run/lldpq-uninstall.active'
SETUP_SAFETY = os.environ.get('SETUP_SAFETY', '')
_CONFIG_LOCK_HANDLE = None
_INVENTORY_LOCK_HANDLE = None
_SSH_KEY_LOCK_HANDLE = None

def load_setup_safety():
    """Load the helper shipped beside this CGI (pure validation/read helpers)."""
    if not SETUP_SAFETY or not os.path.isfile(SETUP_SAFETY):
        raise RuntimeError('Setup safety helper is missing; run install.sh to repair this installation.')
    spec = importlib.util.spec_from_file_location('lldpq_setup_safety', SETUP_SAFETY)
    if spec is None or spec.loader is None:
        raise RuntimeError('Setup safety helper could not be loaded.')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def service_atomic_write(command, target, content, *, expected_revision=None, parser=None):
    """Run the common validator/durable writer as the target-file owner."""
    argv = [SETUP_SAFETY, command, '--target', target]
    for root in (os.environ.get('LLDPQ_DIR'), os.environ.get('WEB_ROOT')):
        if root:
            argv.extend(['--managed-root', root])
    state_dir = os.environ.get('LLDPQ_DIRECT_WRITE_STATE_DIR')
    if state_dir:
        argv.extend(['--direct-write-state-dir', state_dir])
    if parser:
        argv.extend(['--parser', parser])
    if expected_revision is not None:
        argv.extend(['--expected-revision', expected_revision])
    try:
        result = subprocess.run(
            ['sudo', '-n', '-H', '-u', os.environ.get('LLDPQ_USER', 'lldpq'),
             '/usr/bin/bash', '-c', 'exec python3 "$@"', '--'] + argv,
            input=content, capture_output=True, text=True, timeout=30,
        )
    except Exception as exc:
        return {'success': False, 'error': 'Atomic write failed: ' + str(exc)[:300]}
    try:
        response = json.loads(result.stdout)
    except Exception:
        detail = (result.stderr or result.stdout or 'helper returned no result').strip()
        return {'success': False, 'error': 'Atomic write failed: ' + detail[:300]}
    return response

def service_safe_read(target):
    """Recover a retained direct-mount journal and return one locked snapshot."""
    argv = [SETUP_SAFETY, 'read-text', '--target', target]
    for root in (os.environ.get('LLDPQ_DIR'), os.environ.get('WEB_ROOT')):
        if root:
            argv.extend(['--managed-root', root])
    state_dir = os.environ.get('LLDPQ_DIRECT_WRITE_STATE_DIR')
    if state_dir:
        argv.extend(['--direct-write-state-dir', state_dir])
    try:
        result = subprocess.run(
            ['sudo', '-n', '-H', '-u', os.environ.get('LLDPQ_USER', 'lldpq'),
             '/usr/bin/bash', '-c', 'exec python3 "$@"', '--'] + argv,
            capture_output=True, text=True, timeout=30,
        )
    except Exception as exc:
        return {'success': False, 'error': 'Safe read failed: ' + str(exc)[:300]}
    try:
        return json.loads(result.stdout)
    except Exception:
        detail = (result.stderr or result.stdout or 'helper returned no result').strip()
        return {'success': False, 'error': 'Safe read failed: ' + detail[:300]}

def parse_completion_log(content):
    """Return cleaned log and the real exit status recorded by a detached runner."""
    job_matches = list(re.finditer(r'(?m)^__LLDPQ_JOB__:([a-f0-9]{32})\s*$', content))
    log_job_id = job_matches[-1].group(1) if job_matches else None
    matches = list(re.finditer(r'(?m)^__LLDPQ_DONE__(?::(-?[0-9]+))?\s*$', content))
    if not matches:
        display = re.sub(r'(?m)^__LLDPQ_JOB__:[a-f0-9]{32}\s*\n?', '', content).rstrip()
        return display, False, None, False, log_job_id
    raw_code = matches[-1].group(1)
    exit_code = int(raw_code) if raw_code is not None else None
    display = re.sub(r'(?m)^__LLDPQ_DONE__(?::(?:-?[0-9]+)?)?\s*\n?', '', content)
    display = re.sub(r'(?m)^__LLDPQ_JOB__:[a-f0-9]{32}\s*\n?', '', display).rstrip()
    return display, True, exit_code, exit_code == 0, log_job_id

def load_backup_import_helper(module_name):
    """Load only the installer-owned helper, never a service-tree module."""
    try:
        metadata = os.lstat(BACKUP_IMPORT_HELPER)
        parent = os.lstat(os.path.dirname(BACKUP_IMPORT_HELPER))
    except OSError as exc:
        raise RuntimeError(
            'Backup helper is missing; run install.sh to repair this installation.'
        ) from exc
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o755
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise RuntimeError(
            'Backup helper ownership/mode is unsafe; run install.sh to repair this installation.'
        )
    spec = importlib.util.spec_from_file_location(module_name, BACKUP_IMPORT_HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError('Backup helper could not be loaded.')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def call_uninstall_web_helper(command, payload, *, timeout):
    """Call the fixed root-owned uninstall gateway with bounded JSON on stdin."""
    if command not in ('preview', 'start', 'status'):
        return {'success': False, 'error': 'Unsupported uninstall gateway action'}
    try:
        metadata = os.lstat(UNINSTALL_WEB_HELPER)
        parent = os.lstat(os.path.dirname(UNINSTALL_WEB_HELPER))
    except OSError:
        return {
            'success': False,
            'error': 'Uninstall helper is missing; run install.sh to repair this installation.',
        }
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o755
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        return {
            'success': False,
            'error': 'Uninstall helper ownership or permissions are unsafe; run install.sh to repair this installation.',
        }
    try:
        raw_payload = json.dumps(payload, separators=(',', ':'), ensure_ascii=True)
    except (TypeError, ValueError):
        return {'success': False, 'error': 'Uninstall request could not be encoded'}
    if len(raw_payload.encode('utf-8')) > 16384:
        return {'success': False, 'error': 'Uninstall request is too large'}
    try:
        result = subprocess.run(
            ['sudo', '-n', UNINSTALL_WEB_HELPER, command],
            input=raw_payload, capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {'success': False, 'error': 'Uninstall gateway timed out'}
    except Exception as exc:
        return {'success': False, 'error': 'Uninstall gateway failed: ' + str(exc)[:200]}
    if len(result.stdout.encode('utf-8', errors='replace')) > 262144:
        return {'success': False, 'error': 'Uninstall gateway returned too much data'}
    try:
        response = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        detail = (result.stderr or result.stdout or 'no response').strip()
        return {'success': False, 'error': 'Uninstall gateway failed: ' + detail[:300]}
    if not isinstance(response, dict):
        return {'success': False, 'error': 'Uninstall gateway returned an invalid response'}
    if result.returncode != 0 and response.get('success') is not False:
        return {'success': False, 'error': 'Uninstall gateway exited unexpectedly'}
    return response

@contextmanager
def setup_job_start_guard():
    """Serialize run/update reservations against an accepted uninstall."""
    if os.path.exists('/.dockerenv'):
        yield
        return
    try:
        metadata = os.lstat(LIFECYCLE_LOCK_FILE)
    except OSError as exc:
        raise RuntimeError(
            'Lifecycle lock is missing; run install.sh to repair this installation.'
        ) from exc
    try:
        web_gid = grp.getgrnam('www-data').gr_gid
    except KeyError as exc:
        raise RuntimeError('Required www-data group is unavailable') from exc
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_gid != web_gid or stat.S_IMODE(metadata.st_mode) != 0o660
            or metadata.st_nlink != 1):
        raise RuntimeError('Lifecycle lock has unsafe ownership or permissions')
    flags = os.O_RDWR | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(LIFECYCLE_LOCK_FILE, flags)
    try:
        opened = os.fstat(descriptor)
        if ((opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                or not stat.S_ISREG(opened.st_mode)):
            raise RuntimeError('Lifecycle lock changed while opening')
        deadline = time.monotonic() + 3.0
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        'Another LLDPq install, update or uninstall lifecycle operation is active'
                    ) from exc
                time.sleep(0.05)
        if os.path.lexists(UNINSTALL_ACTIVE_MARKER):
            marker = os.lstat(UNINSTALL_ACTIVE_MARKER)
            if (not stat.S_ISREG(marker.st_mode) or marker.st_uid != 0
                    or marker.st_gid != 0 or stat.S_IMODE(marker.st_mode) != 0o644
                    or marker.st_nlink != 1 or marker.st_size > 128):
                raise RuntimeError('Uninstall lifecycle marker is unsafe; inspect the host')
            raise RuntimeError('An LLDPq uninstall is already scheduled or running')
        # The uninstaller removes its fixed gateway while holding this same
        # lock. A request that was already waiting on the now-unlinked lock
        # must still fail after the marker is retired; it may not launch work
        # against a dismantled installation.
        try:
            helper = os.lstat(UNINSTALL_WEB_HELPER)
        except OSError as exc:
            raise RuntimeError('LLDPq uninstall/install lifecycle is no longer available') from exc
        if (not stat.S_ISREG(helper.st_mode) or helper.st_uid != 0
                or helper.st_gid != 0 or stat.S_IMODE(helper.st_mode) != 0o755
                or helper.st_nlink != 1):
            raise RuntimeError('LLDPq lifecycle helper has unsafe ownership or permissions')
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

def ensure_configuration_lock():
    """Serialize all /etc/lldpq.conf + cron transactions in this CGI."""
    global _CONFIG_LOCK_HANDLE
    if _CONFIG_LOCK_HANDLE is not None:
        return
    path = '/etc/lldpq.conf.lock'
    metadata = os.lstat(path)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & stat.S_IWOTH):
        raise RuntimeError('Global configuration lock has unsafe ownership, type, or permissions.')
    flags = os.O_RDWR | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
        os.close(descriptor)
        raise RuntimeError('Global configuration lock changed while opening.')
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    _CONFIG_LOCK_HANDLE = os.fdopen(descriptor, 'r+')

def ensure_inventory_lock():
    """Serialize backup snapshots/restores with Provision inventory writers."""
    global _INVENTORY_LOCK_HANDLE
    if _INVENTORY_LOCK_HANDLE is not None:
        return
    path = os.path.join(os.environ.get('WEB_ROOT', '/var/www/html'), '.inventory.lock')
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_CLOEXEC', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags, 0o664)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & stat.S_IWOTH:
            raise RuntimeError('Inventory lock has unsafe type or permissions.')
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except Exception:
        os.close(descriptor)
        raise
    _INVENTORY_LOCK_HANDLE = os.fdopen(descriptor, 'r+')

def ensure_backup_locks():
    """Use the shared global -> inventory order for portable config bundles."""
    ensure_configuration_lock()
    ensure_inventory_lock()

def ensure_ssh_key_lock():
    """Lock order is global configuration first, then the SSH-key transaction."""
    global _SSH_KEY_LOCK_HANDLE
    if _SSH_KEY_LOCK_HANDLE is not None:
        return
    ensure_configuration_lock()
    path = '/var/lib/lldpq/ssh-key.lock'
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise RuntimeError('SSH key lock is missing; run install.sh to repair this installation.') from exc
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & stat.S_IWOTH):
        raise RuntimeError('SSH key lock has unsafe ownership, type, or permissions.')
    flags = os.O_RDWR | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
        os.close(descriptor)
        raise RuntimeError('SSH key lock changed while opening.')
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    _SSH_KEY_LOCK_HANDLE = os.fdopen(descriptor, 'r+')

def valid_cron_schedule(schedule):
    if not isinstance(schedule, str):
        return False
    try:
        return subprocess.run(
            [CRON_VALIDATOR, '--validate-cron', schedule],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
        ).returncode == 0
    except Exception:
        return False

def load_devices(devices_yaml):
    """Load devices through the same canonical parser used by collectors."""
    parser_path = os.path.join(os.path.dirname(devices_yaml), 'parse_devices.py')
    if not os.path.isfile(parser_path):
        return None, 'Canonical device parser is missing: ' + parser_path
    try:
        parsed = subprocess.run(
            [sys.executable, parser_path, '--format', 'json', '--file', devices_yaml],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as e:
        return None, str(e)
    if parsed.returncode != 0:
        return None, (parsed.stderr or 'Device inventory is invalid').strip()[:300]
    try:
        records = json.loads(parsed.stdout)
        if not isinstance(records, list) or not records:
            raise ValueError('No devices found in devices.yaml')
        devices = [
            {
                'ip': record['address'],
                'hostname': record['hostname'],
                'username': record['username'],
            }
            for record in records
        ]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as e:
        return None, 'Invalid canonical device data: ' + str(e)
    return devices, None

def _as_service(argv, *, input_text=None, timeout=10):
    return subprocess.run(
        ['sudo', '-n', '-u', os.environ.get('LLDPQ_USER', 'lldpq')] + argv,
        input=input_text, capture_output=True, text=True, timeout=timeout,
    )

def _read_service_file(path):
    try:
        result = _as_service(['/usr/bin/cat', path], timeout=5)
    except Exception:
        return None
    return result.stdout if result.returncode == 0 else None

def cleanup_uploaded_tarball(path):
    """Delete only a regular upload buffer created by this CGI principal."""
    if not isinstance(path, str) or not re.fullmatch(
            r'/tmp/lldpq-upload-src\.[A-Za-z0-9]{6}\.tar\.gz', path):
        return False
    try:
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            return False
        os.unlink(path)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False

def _public_key_identity(value):
    parts = (value or '').strip().split()
    return tuple(parts[:2]) if len(parts) >= 2 else None

def validate_ssh_key_pair(private_path):
    """Return the canonical public key only when the private key is usable."""
    try:
        private = _read_service_file(private_path)
        if not private or 'PRIVATE KEY' not in private:
            return None, 'Private key is missing or unreadable'
        derived = _as_service(
            ['/usr/bin/ssh-keygen', '-y', '-f', private_path], timeout=10,
        )
        if derived.returncode != 0 or not _public_key_identity(derived.stdout):
            return None, 'ssh-keygen could not validate the private key'
        existing = _read_service_file(private_path + '.pub')
        if existing is None:
            return None, 'Public key is missing'
        if _public_key_identity(existing) != _public_key_identity(derived.stdout):
            return None, 'Public key does not match the collector private key'
        return derived.stdout.strip() + '\n', None
    except Exception as exc:
        return None, str(exc)

def ensure_ssh_key(lldpq_user):
    """Return a validated collector public key path, generating only if none exists."""
    ssh_dir = os.path.expanduser(f'~{lldpq_user}/.ssh')
    invalid = []
    any_key_material = False
    for key_name in ('id_ed25519', 'id_rsa'):
        private_path = os.path.join(ssh_dir, key_name)
        private = _read_service_file(private_path)
        public = _read_service_file(private_path + '.pub')
        if private is None and public is None:
            continue
        any_key_material = True
        canonical, error = validate_ssh_key_pair(private_path)
        if canonical:
            return private_path + '.pub', False, None
        invalid.append(f'{key_name}: {error}')
    if any_key_material:
        return None, False, ('Collector key material is incomplete or inconsistent; refusing to overwrite it. '
                             + '; '.join(invalid))

    key_path = os.path.join(ssh_dir, 'id_ed25519')
    try:
        made = _as_service(['/usr/bin/mkdir', '-p', ssh_dir], timeout=10)
        if made.returncode != 0:
            return None, False, 'Could not create the collector .ssh directory'
        # ssh-keygen uses exclusive creation.  With no prior key material this is
        # safe, and a concurrent request will simply lose without replacing a key.
        generated = _as_service(
            ['/usr/bin/ssh-keygen', '-t', 'ed25519', '-N', '', '-f', key_path],
            timeout=15,
        )
        if generated.returncode != 0:
            return None, False, 'ssh-keygen failed: ' + (generated.stderr or '').strip()[:200]
        canonical, error = validate_ssh_key_pair(key_path)
        if not canonical:
            return None, False, 'Generated collector key failed validation: ' + str(error)
        return key_path + '.pub', True, None
    except Exception as exc:
        return None, False, str(exc)

def setup_device(device, password, ssh_key_path, lldpq_user):
    """Run send-key + sudo-fix for a single device. Returns result dict."""
    ip = device['ip']
    username = device['username']
    hostname = device['hostname']
    
    result = {
        'hostname': hostname,
        'ip': ip,
        'username': username,
        'send_key': 'skipped',
        'sudo_fix': 'skipped',
        'send_key_msg': '',
        'sudo_fix_msg': ''
    }
    
    # Step 1: Check if key already works
    priv_key = ssh_key_path[:-4] if ssh_key_path.endswith('.pub') else ssh_key_path
    ssh_base = [
        'sudo', '-n', '-u', lldpq_user, 'ssh',
        '-i', priv_key, '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no',
        '-q', f'{username}@{ip}',
    ]
    try:
        check = subprocess.run(
            ssh_base + ['true'],
            capture_output=True, text=True, timeout=10
        )
        if check.returncode == 0:
            result['send_key'] = 'already'
            result['send_key_msg'] = 'Key already configured'
        else:
            raise Exception('Key not configured')
    except Exception:
        # Key not configured - send it
        try:
            send = subprocess.run(
                ['sudo', '-n', '-u', lldpq_user, '/usr/bin/bash', '-c',
                 'IFS= read -r SSHPASS || exit 2; export SSHPASS; exec sshpass -e ssh-copy-id "$@"',
                 '--', '-o', 'StrictHostKeyChecking=no',
                 '-o', 'IdentitiesOnly=yes', '-i', ssh_key_path,
                 f'{username}@{ip}'],
                input=password + '\n', capture_output=True, text=True, timeout=30,
            )
            if send.returncode == 0:
                result['send_key'] = 'ok'
                result['send_key_msg'] = 'Key sent successfully'
            else:
                result['send_key'] = 'fail'
                result['send_key_msg'] = send.stderr.strip()[:200] if send.stderr else 'ssh-copy-id failed'
        except subprocess.TimeoutExpired:
            result['send_key'] = 'fail'
            result['send_key_msg'] = 'Timeout (30s)'
        except Exception as e:
            result['send_key'] = 'fail'
            result['send_key_msg'] = str(e)[:200]
    
    # Step 2: Setup sudo (only if send-key succeeded or already configured)
    if result['send_key'] in ('ok', 'already'):
        try:
            sudo_check = subprocess.run(
                ssh_base + ['sudo -n true'], capture_output=True, text=True, timeout=15,
            )
            if sudo_check.returncode == 0:
                result['sudo_fix'] = 'ok'
                result['sudo_fix_msg'] = 'Passwordless sudo already configured'
            else:
                # The password and sudoers line are data on stdin.  Neither is
                # interpolated into a local or remote shell command.
                remote = (
                    "sudo -S -p '' /bin/sh -c '"
                    "umask 077; t=$(mktemp /etc/sudoers.d/.10_lldpq_collector.XXXXXX) || exit 1; "
                    "cat >\"$t\" || { rm -f \"$t\"; exit 1; }; chmod 440 \"$t\" || exit 1; "
                    "if command -v visudo >/dev/null 2>&1; then visudo -cf \"$t\" >/dev/null || { rm -f \"$t\"; exit 1; }; fi; "
                    "mv -f \"$t\" /etc/sudoers.d/10_lldpq_collector'"
                )
                payload = password + '\n' + username + ' ALL=(ALL) NOPASSWD:ALL\n'
                sudo = subprocess.run(
                    ssh_base[:-2] + [f'{username}@{ip}', remote],
                    input=payload, capture_output=True, text=True, timeout=30,
                )
                verified = subprocess.run(
                    ssh_base + ['sudo -n true'], capture_output=True, text=True, timeout=15,
                ) if sudo.returncode == 0 else sudo
                if sudo.returncode == 0 and verified.returncode == 0:
                    result['sudo_fix'] = 'ok'
                    result['sudo_fix_msg'] = 'Sudo configured and verified'
                else:
                    result['sudo_fix'] = 'fail'
                    detail = (sudo.stderr or verified.stderr or 'sudo setup failed').strip()
                    result['sudo_fix_msg'] = detail[:200]
        except subprocess.TimeoutExpired:
            result['sudo_fix'] = 'fail'
            result['sudo_fix_msg'] = 'Timeout (30s)'
        except Exception as e:
            result['sudo_fix'] = 'fail'
            result['sudo_fix_msg'] = str(e)[:200]
    else:
        result['sudo_fix'] = 'skipped'
        result['sudo_fix_msg'] = 'Skipped (send-key failed)'
    
    return result

def read_private_request_json():
    path = os.environ.get('POST_DATA_FILE', '')
    if not path:
        raise ValueError('Private request buffer is missing')
    metadata = os.lstat(path)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise ValueError('Private request buffer has unsafe metadata')
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    opened = os.fstat(descriptor)
    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
        os.close(descriptor)
        raise ValueError('Private request buffer changed while opening')
    try:
        os.unlink(path)
        with os.fdopen(descriptor, 'rb') as source:
            raw = source.read(33554433)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    if len(raw) > 33554432:
        raise ValueError('JSON request exceeds the 32 MiB limit')
    def reject_duplicate_keys(pairs):
        result = {}
        seen = {}
        for key, value in pairs:
            folded = key.casefold()
            if folded in seen:
                raise ValueError(
                    'JSON request contains a duplicate key: '
                    + repr(seen[folded]) + ' and ' + repr(key)
                )
            seen[folded] = key
            result[key] = value
        return result
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('Invalid JSON: ' + str(exc)) from exc

# Main
try:
    post_data = read_private_request_json()
except Exception as exc:
    print(json.dumps({'success': False, 'error': str(exc)[:300]}))
    sys.exit(0)
if not isinstance(post_data, dict):
    print(json.dumps({'success': False, 'error': 'JSON request must be an object'}))
    sys.exit(0)

lldpq_user = os.environ.get('LLDPQ_USER', 'lldpq')
lldpq_dir = os.environ.get('LLDPQ_DIR', '/home/lldpq/lldpq')
web_root = os.environ.get('WEB_ROOT', '/var/www/html')
config_owner = f'{lldpq_user}:www-data'
devices_yaml = os.path.join(lldpq_dir, 'devices.yaml')

# /etc/lldpq.conf keys that are portable (safe to carry in a backup): tunable knobs only.
# NEVER include host paths/identity (LLDPQ_DIR/USER/SRC, WEB_ROOT, *_DIR, DHCP_*, DISCOVERY_RANGE)
# or secrets (AI_API_KEY).
LLDPQ_PREF_KEYS = (
    'LLDPQ_CRON', 'GETCONF_CRON', 'SCAN_INTERVAL', 'SKIP_OPTICAL', 'SKIP_L1',
    'MONITOR_TIMING', 'MONITOR_MAX_PARALLEL', 'MONITOR_COMMAND_TIMEOUT_SECONDS',
    'PFC_ECN_MAX_PARALLEL',
    'PFC_ECN_COLLECTION_BUDGET_SECONDS', 'PFC_ECN_PORT_TIMEOUT_SECONDS',
    'OPTICAL_COLLECTION_BUDGET_SECONDS', 'OPTICAL_PORT_TIMEOUT_SECONDS',
    'LLDP_MAX_PARALLEL', 'ASSETS_MAX_PARALLEL',
    'GET_CONFIGS_MAX_PARALLEL', 'GET_CONFIGS_SSH_TIMEOUT',
    'SEND_CMD_MAX_PARALLEL', 'TELEMETRY_MAX_PARALLEL',
    'AUTO_BASE_CONFIG', 'AUTO_ZTP_DISABLE', 'AUTO_SET_HOSTNAME',
    'TRANSCEIVER_FW_SKIP_MODELS', 'TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY',
    'TRANSCEIVER_FW_MAX_PARALLEL', 'TRANSCEIVER_FW_MIN_INTERVAL', 'TRANSCEIVER_FW_SSH_TIMEOUT',
    'TELEMETRY_ENABLED', 'PROMETHEUS_URL', 'AI_PROVIDER', 'AI_MODEL', 'AI_API_URL', 'OLLAMA_URL',
    'AI_FALLBACK_MODEL', 'AI_CONTEXT_WINDOW_TOKENS',
    'AI_FALLBACK_CONTEXT_WINDOW_TOKENS', 'AI_PROXY_URL', 'AI_SEARCH_MODEL',
    'AI_SEARCH_URL',
)
action = post_data.get('action', 'setup')

def read_conf():
    """Read /etc/lldpq.conf into a dict (group-readable by www-data)."""
    ensure_configuration_lock()
    conf = {}
    try:
        with open('/etc/lldpq.conf') as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    conf[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return conf

def install_text_as_root(content, target, temp_name, mode='644', owner='root:root'):
    """Install privileged text through the root-owned atomic bundle helper."""
    ensure_configuration_lock()
    try:
        user_name, group_name = owner.split(':', 1)
        uid = int(user_name) if user_name.isdigit() else pwd.getpwnam(user_name).pw_uid
        gid = int(group_name) if group_name.isdigit() else grp.getgrnam(group_name).gr_gid
        helper = load_backup_import_helper('lldpq_root_atomic_write')
        helper._install_bytes_as_root(
            content.encode('utf-8'), target, int(mode, 8), uid, gid,
        )
        return True
    except Exception:
        return False

def write_conf(pairs):
    """Update allowlisted key=value pairs without nested sudo shells."""
    if not pairs:
        return True
    ensure_configuration_lock()
    try:
        original = open('/etc/lldpq.conf').read()
    except Exception:
        return False
    current = original.splitlines()
    keys = set(pairs)
    output = []
    for line in current:
        stripped = line.strip()
        key = stripped.split('=', 1)[0].strip() if '=' in stripped else ''
        if stripped and not stripped.startswith('#') and key in keys:
            continue
        output.append(line)
    output.extend('%s=%s' % (key, value) for key, value in pairs.items())
    if install_text_as_root(
        '\n'.join(output) + '\n', '/etc/lldpq.conf', '.lldpq.conf.setup.tmp',
        '660', config_owner
    ):
        return True
    # A copy can succeed before a later chmod/chown failure. Restore the exact
    # original bytes before reporting failure so callers get a transaction.
    install_text_as_root(
        original, '/etc/lldpq.conf', '.lldpq.conf.setup.rollback.tmp',
        '660', config_owner
    )
    return False

def reserve_background_job(state_dir, kind, log_path):
    """Atomically reserve one service-user job slot and return a unique id."""
    job_id = uuid.uuid4().hex
    active = os.path.join(state_dir, kind + '.active')
    pid_path = os.path.join(state_dir, kind + '.pid')
    script = r'''
set -u
active=$1; pidfile=$2; job=$3; logfile=$4
exec 9>"${active%.active}.start.lock" || exit 76
flock -x 9 || exit 76
if ! mkdir "$active" 2>/dev/null; then
  pid_record=""; pid=""; pid_job=""; pid_start=""; extra=""
  [ -f "$pidfile" ] && IFS= read -r pid_record < "$pidfile"
  read -r first second third extra <<< "$pid_record"
  if [[ "$first" =~ ^[a-f0-9]{32}$ ]] && [[ "$second" =~ ^[1-9][0-9]*$ ]] && [ -z "$extra" ]; then
    pid_job=$first; pid=$second
    [[ "$third" =~ ^[1-9][0-9]*$ ]] && pid_start=$third
  elif [[ "$first" =~ ^[1-9][0-9]*$ ]] && [ -z "$second" ]; then
    pid=$first
  fi
  current_job=$(cat "$active/job_id" 2>/dev/null || true)
  now=$(date +%s); mt=$(stat -c %Y "$active" 2>/dev/null || stat -f %m "$active" 2>/dev/null || echo "$now")
  age=$((now-mt)); [ "$age" -lt 0 ] && age=0
  if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && { [ -z "$pid_job" ] || [ "$pid_job" = "$current_job" ]; } \
     && kill -0 "$pid" 2>/dev/null; then
    if [ -n "$pid_start" ]; then
      current_start=$(awk '{print $22}' "/proc/$pid/stat" 2>/dev/null || true)
      [ "$current_start" = "$pid_start" ] && exit 75
    elif [ "$age" -lt 120 ]; then
      # Legacy one/two-field records have no process generation. Trust them
      # only during the startup grace period so PID reuse cannot block forever.
      exit 75
    fi
  fi
  if [ "$age" -lt 120 ]; then exit 75; fi
  rm -f "$active/job_id" "$active/created" 2>/dev/null || exit 76
  rmdir "$active" 2>/dev/null || exit 76
  mkdir "$active" 2>/dev/null || exit 75
fi
printf '%s\n' "$job" > "$active/job_id" || exit 76
date +%s > "$active/created" || exit 76
printf '%s\n' "$job" > "${active%.active}.last-job" || exit 76
printf '__LLDPQ_JOB__:%s\n' "$job" > "$logfile" || exit 76
'''
    result = subprocess.run(
        ['sudo', '-n', '-u', lldpq_user, '/usr/bin/bash', '-c', script,
         '--', active, pid_path, job_id, log_path],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode == 0:
        return job_id, None
    if result.returncode == 75:
        return None, f'Another {kind} job is already active'
    release_background_job(state_dir, kind, job_id)
    return None, f'Could not reserve the {kind} job slot: ' + (result.stderr or '').strip()[:160]

def release_background_job(state_dir, kind, expected_job_id=None):
    if not expected_job_id:
        return
    active = os.path.join(state_dir, kind + '.active')
    pid_path = os.path.join(state_dir, kind + '.pid')
    subprocess.run(
         ['sudo', '-n', '-u', lldpq_user, '/usr/bin/bash', '-c',
         'exec 9>"${1%.active}.start.lock" || exit 1; flock -x 9 || exit 1; '
         'current=$(cat "$1/job_id" 2>/dev/null || true); '
         'if [ -z "$current" ] || [ "$current" = "$3" ]; then '
         'rm -f "$1/job_id" "$1/created" "$2" 2>/dev/null; rmdir "$1" 2>/dev/null || true; fi',
         '--', active, pid_path, expected_job_id or ''],
        capture_output=True, text=True, timeout=10,
    )

def background_job_status(state_dir, kind, raw_done, log_job_id):
    """Return job status and retire detached-launch reservations that went stale."""
    active = os.path.join(state_dir, kind + '.active')
    pid_path = os.path.join(state_dir, kind + '.pid')
    active_exists = os.path.isdir(active)
    active_job_id = (_read_service_file(os.path.join(active, 'job_id')) or '').strip()
    last_job_id = (_read_service_file(os.path.join(state_dir, kind + '.last-job')) or '').strip()
    job_id = active_job_id if active_exists else last_job_id
    pid_text = (_read_service_file(pid_path) or '').strip()
    pid_job_id = None
    pid_value = ''
    pid_start = None
    pid_match = re.fullmatch(
        r'([a-f0-9]{32})\s+([1-9][0-9]*)(?:\s+([1-9][0-9]*))?',
        pid_text,
    )
    if pid_match:
        pid_job_id, pid_value, pid_start = pid_match.groups()
    elif re.fullmatch(r'[1-9][0-9]*', pid_text):
        # Compatibility with reservations created before job IDs were stored.
        pid_value = pid_text
    pid_recorded = bool(pid_value)
    if pid_job_id and job_id and pid_job_id != job_id:
        pid_recorded = False
    done = load_setup_safety().completion_belongs_to_job(
        raw_done=raw_done, log_job_id=log_job_id,
        known_job_id=job_id or None, active_exists=active_exists,
    )
    age = 0
    if active_exists:
        created_text = (_read_service_file(os.path.join(active, 'created')) or '').strip()
        try:
            age = max(0, time.time() - int(created_text))
        except (TypeError, ValueError):
            try:
                age = max(0, time.time() - os.stat(active).st_mtime)
            except OSError:
                age = 121
    process_alive = False
    if pid_recorded:
        try:
            os.kill(int(pid_value), 0)
            kill_alive = True
        except PermissionError:
            kill_alive = True
        except ProcessLookupError:
            kill_alive = False
        if kill_alive and pid_start is not None:
            try:
                raw_stat = open(f'/proc/{pid_value}/stat', encoding='ascii').read(4096)
                stat_fields = raw_stat.rsplit(') ', 1)[1].split()
                current_start = stat_fields[19]
            except (OSError, IndexError, UnicodeError):
                current_start = None
            process_alive = current_start == pid_start
        elif kill_alive:
            # A legacy PID-only record cannot distinguish a reused PID. Keep
            # only the same bounded grace used by reservation recovery.
            process_alive = active_exists and age < 120
    decision = load_setup_safety().classify_background_job(
        done=done, process_alive=process_alive,
        active_exists=active_exists, age_seconds=age,
    )
    if job_id and done and (active_exists or pid_recorded):
        release_background_job(state_dir, kind, job_id)
    elif job_id and decision['stale_reservation']:
        release_background_job(state_dir, kind, job_id)
    return {'running': decision['running'], 'pid_recorded': pid_recorded,
            'job_id': job_id or None,
            'stale_reservation': decision['stale_reservation'], 'done': done}

def active_setup_job_names():
    """Return active collector/update jobs that must not race an uninstall."""
    state_dir = os.path.join(os.path.expanduser('~' + lldpq_user), '.lldpq-state')
    jobs = (
        ('run', os.path.join(lldpq_dir, '.run.log')),
        ('update', os.path.join(state_dir, 'update.log')),
    )
    active = []
    for kind, log_path in jobs:
        content = _read_service_file(log_path) or ''
        _display, raw_done, _exit_code, _ok, log_job_id = parse_completion_log(content)
        status = background_job_status(state_dir, kind, raw_done, log_job_id)
        if status['running']:
            active.append(kind)
    return active

def validated_uninstall_request(*, start=False):
    """Copy only the fixed uninstall schema; reject extras and type coercion."""
    allowed_top = {'action', 'options', 'acknowledgements'}
    if start:
        allowed_top.update({
            'preview_token', 'preview_fingerprint', 'confirmation', 'request_id',
        })
    unknown_top = set(post_data) - allowed_top
    if unknown_top:
        raise ValueError('Unsupported uninstall request field: ' + sorted(unknown_top)[0])

    options = post_data.get('options')
    option_names = {
        'keep_data', 'remove_source', 'remove_nginx', 'remove_dhcp', 'remove_docker',
    }
    if not isinstance(options, dict) or set(options) != option_names:
        raise ValueError('Uninstall options must contain exactly the supported fields')
    if any(not isinstance(options[name], bool) for name in option_names):
        raise ValueError('Every uninstall option must be true or false')

    acknowledgements = post_data.get('acknowledgements', {})
    acknowledgement_names = {'ack_disconnect', 'ack_data_loss', 'ack_shared_services'}
    if (not isinstance(acknowledgements, dict)
            or set(acknowledgements) != acknowledgement_names
            or any(not isinstance(value, bool) for value in acknowledgements.values())):
        raise ValueError('Uninstall acknowledgements are invalid')
    acknowledgements = {name: acknowledgements[name] for name in acknowledgement_names}

    payload = {'options': dict(options), 'acknowledgements': acknowledgements}
    if not start:
        return payload

    confirmation = post_data.get('confirmation')
    if confirmation != 'UNINSTALL':
        raise ValueError('Type UNINSTALL exactly to confirm')
    if not acknowledgements['ack_disconnect']:
        raise ValueError('The management-disconnect acknowledgement is required')
    if ((not options['keep_data'] or options['remove_source'])
            and not acknowledgements['ack_data_loss']):
        raise ValueError('The permanent data-loss acknowledgement is required')
    if (any(options[name] for name in ('remove_nginx', 'remove_dhcp', 'remove_docker'))
            and not acknowledgements['ack_shared_services']):
        raise ValueError('The shared-service removal acknowledgement is required')

    token = post_data.get('preview_token')
    fingerprint = post_data.get('preview_fingerprint', '')
    request_id = post_data.get('request_id')
    if not isinstance(token, str) or not re.fullmatch(r'[a-f0-9]{64}', token):
        raise ValueError('A valid dry-run preview token is required')
    if (not isinstance(fingerprint, str)
            or not re.fullmatch(r'[a-f0-9]{64}', fingerprint)):
        raise ValueError('The preview fingerprint is invalid')
    if (not isinstance(request_id, str)
            or not re.fullmatch(r'[a-f0-9]{32}', request_id)):
        raise ValueError('The uninstall request ID is invalid')
    payload.update({
        'preview_token': token,
        'preview_fingerprint': fingerprint,
        'confirmation': confirmation,
        'request_id': request_id,
    })
    return payload

# ─── Actions: Native uninstall Danger Zone (root-owned fixed gateway) ───
if action in ('uninstall-preview', 'uninstall-start'):
    if os.path.exists('/.dockerenv'):
        response = {
            'success': False,
            'docker': True,
            'error': ('Docker deployment: uninstall LLDPq from the Docker host with '
                      'docker compose down and remove the host deployment files there.'),
        }
        if action == 'uninstall-start':
            response['accepted'] = False
        print(json.dumps(response))
        sys.exit(0)
    try:
        payload = validated_uninstall_request(start=action == 'uninstall-start')
        conflicts = active_setup_job_names()
    except Exception as exc:
        response = {'success': False, 'error': str(exc)[:300]}
        if action == 'uninstall-start':
            response['accepted'] = False
        print(json.dumps(response))
        sys.exit(0)
    if conflicts:
        response = {
            'success': False,
            'conflict': True,
            'error': 'Cannot uninstall while Setup jobs are active: ' + ', '.join(conflicts),
        }
        if action == 'uninstall-start':
            response['accepted'] = False
        print(json.dumps(response))
        sys.exit(0)
    command = 'start' if action == 'uninstall-start' else 'preview'
    response = call_uninstall_web_helper(
        command, payload, timeout=30 if command == 'start' else 180,
    )
    print(json.dumps(response))
    sys.exit(0)

if action == 'uninstall-status':
    if set(post_data) != {'action', 'job_id'}:
        print(json.dumps({'success': False, 'error': 'Uninstall status request is invalid'}))
        sys.exit(0)
    job_id = post_data.get('job_id')
    if (not isinstance(job_id, str)
            or not re.fullmatch(r'[a-f0-9]{32}', job_id)):
        print(json.dumps({'success': False, 'error': 'Uninstall job ID is invalid'}))
        sys.exit(0)
    response = call_uninstall_web_helper('status', {'job_id': job_id}, timeout=20)
    print(json.dumps(response))
    sys.exit(0)

# ─── Actions: Read/write display-only P2P and field aliases ───
if action == 'get-aliases':
    alias_file = os.path.join(web_root, 'display-aliases.json')
    try:
        snapshot = service_safe_read(alias_file)
        if not snapshot.get('success'):
            raise RuntimeError(snapshot.get('error', 'safe read failed'))
        safety = load_setup_safety()
        if snapshot.get('exists'):
            value = safety.parse_json_no_duplicate_keys(
                snapshot.get('content', ''), 'display-aliases.json'
            )
            aliases = safety.normalize_aliases(value)
        else:
            aliases = {'interfaces': {}, 'devices': {}}
        revision = snapshot['revision']
        print(json.dumps({'success': True, 'aliases': aliases, 'revision': revision}))
    except Exception as exc:
        print(json.dumps({'success': False, 'error': 'Cannot load display aliases: ' + str(exc)[:300]}))
    sys.exit(0)

if action == 'set-aliases':
    alias_file = os.path.join(web_root, 'display-aliases.json')
    raw_aliases = post_data.get('aliases')
    if raw_aliases is None:
        raw_aliases = {
            'interfaces': post_data.get('interfaces', {}),
            'devices': post_data.get('devices', {}),
        }
    expected = post_data.get('expected_revision', post_data.get('revision'))
    if expected is not None and not isinstance(expected, str):
        print(json.dumps({'success': False, 'error': 'revision must be a string'}))
        sys.exit(0)
    try:
        safety = load_setup_safety()
        aliases, rendered = safety.aliases_text(raw_aliases)
    except Exception as exc:
        print(json.dumps({'success': False, 'error': str(exc)[:300]}))
        sys.exit(0)
    response = service_atomic_write(
        'save-aliases', alias_file, rendered, expected_revision=expected,
    )
    if response.get('success'):
        response['aliases'] = aliases
        response['message'] = (
            'Display aliases saved through a journaled legacy direct-file mount'
            if response.get('atomic') is False else 'Display aliases saved successfully'
        )
    print(json.dumps(response))
    sys.exit(0)

# ─── Action: Save existing private key ───
if action == 'save-key':
    # This legacy endpoint used to overwrite the live private key before it had
    # been validated.  Setup no longer calls it; key import is handled by the
    # staged/rollback-capable Provision key API.  Fail closed so old clients
    # cannot reintroduce the destructive path.
    print(json.dumps({
        'success': False,
        'deprecated': True,
        'error': 'Legacy direct key import is disabled. Use Setup → SSH Keys → Import, which validates and stages the key before replacement.'
    }))
    sys.exit(0)

# ─── Action: Export the collector PRIVATE key (back up / migrate LLDPq to another host) ───
if action == 'get-private-key':
    try:
        ensure_ssh_key_lock()
    except Exception as exc:
        print(json.dumps({'success': False, 'error': str(exc)}))
        sys.exit(0)
    private_key = ''
    key_file = ''
    for key_name in ('id_ed25519', 'id_rsa'):
        p = os.path.expanduser(f'~{lldpq_user}/.ssh/{key_name}')
        try:
            canonical, pair_error = validate_ssh_key_pair(p)
            candidate = _read_service_file(p)
            if canonical and candidate:
                private_key = candidate
                key_file = p
                break
        except Exception:
            pass
    if private_key:
        print(json.dumps({'success': True, 'private_key': private_key, 'key_file': key_file}))
    else:
        print(json.dumps({'success': False, 'error': f'No private key found for {lldpq_user}'}))
    sys.exit(0)

# ─── Action: Verify which devices already trust the collector key (no password) ───
if action == 'verify':
    try:
        ensure_ssh_key_lock()
    except Exception as exc:
        print(json.dumps({'success': False, 'error': str(exc)}))
        sys.exit(0)
    all_devices, load_error = load_devices(devices_yaml)
    if load_error:
        print(json.dumps({'success': False, 'error': load_error}))
        sys.exit(0)

    ssh_key_path, key_generated, key_error = ensure_ssh_key(lldpq_user)
    if key_error:
        print(json.dumps({'success': False, 'error': 'SSH key error: ' + key_error}))
        sys.exit(0)
    private_key_path = ssh_key_path[:-4] if ssh_key_path.endswith('.pub') else ssh_key_path
    public_key, pair_error = validate_ssh_key_pair(private_key_path)
    if pair_error:
        print(json.dumps({'success': False, 'error': 'SSH key error: ' + pair_error}))
        sys.exit(0)

    def verify_device(device):
        ip = device['ip']
        username = device['username']
        res = {'hostname': device['hostname'], 'ip': ip, 'username': username,
               'trusted': False, 'msg': '', 'sudo_ok': False, 'sudo_msg': ''}
        base = ['sudo', '-n', '-u', lldpq_user, 'ssh', '-i', private_key_path,
                '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
                '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no',
                '-q', f'{username}@{ip}']
        try:
            chk = subprocess.run(
                base + ['true'],
                capture_output=True, text=True, timeout=10
            )
            if chk.returncode == 0:
                res['trusted'] = True
                res['msg'] = 'Key trusted'
                sudo_check = subprocess.run(
                    base + ['sudo -n true'], capture_output=True, text=True, timeout=10,
                )
                if sudo_check.returncode == 0:
                    res['sudo_ok'] = True
                    res['sudo_msg'] = 'Passwordless sudo ready'
                else:
                    res['sudo_msg'] = 'Key works, but passwordless sudo is not ready'
            else:
                res['msg'] = 'Key not accepted (needs distribution)'
                res['sudo_msg'] = 'Sudo not checked because key authentication failed'
        except subprocess.TimeoutExpired:
            res['msg'] = 'Timeout (10s)'
            res['sudo_msg'] = 'Sudo not checked'
        except Exception as e:
            res['msg'] = str(e)[:120]
            res['sudo_msg'] = 'Sudo not checked'
        return res

    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(verify_device, d): d for d in all_devices}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                d = futures[future]
                results.append({'hostname': d['hostname'], 'ip': d['ip'], 'username': d['username'],
                                'trusted': False, 'msg': str(e)[:120],
                                'sudo_ok': False, 'sudo_msg': 'Sudo not checked'})
    results.sort(key=lambda r: r['hostname'])

    trusted = sum(1 for r in results if r['trusted'])
    sudo_ok = sum(1 for r in results if r['sudo_ok'])
    print(json.dumps({'success': True, 'total': len(results), 'trusted': trusted,
                      'sudo_ok': sudo_ok, 'ready': sudo_ok,
                      'key_generated': key_generated,
                      'public_key': public_key.strip(), 'results': results}))
    sys.exit(0)

# ─── Action: Run the full LLDPq pipeline verbosely (lldpq -) into a log we can tail ───
if action == 'run':
    log_path = os.path.join(lldpq_dir, '.run.log')
    state_dir = os.path.join(os.path.expanduser('~' + lldpq_user), '.lldpq-state')
    subprocess.run(['sudo', '-n', '-u', lldpq_user, '/usr/bin/mkdir', '-p', state_dir],
                   capture_output=True, text=True, timeout=10)
    try:
        with setup_job_start_guard():
            job_id, job_error = reserve_background_job(state_dir, 'run', log_path)
    except Exception as exc:
        print(json.dumps({'success': False, 'conflict': True,
                          'error': 'Could not reserve the LLDPq run: ' + str(exc)[:200]}))
        sys.exit(0)
    if job_error:
        print(json.dumps({'success': False, 'conflict': True, 'error': job_error}))
        sys.exit(0)
    pid_path = os.path.join(state_dir, 'run.pid')
    active_path = os.path.join(state_dir, 'run.active')
    start_lock_path = os.path.join(state_dir, 'run.start.lock')
    cleanup = (
        f'rc=$?; exec 8>{shlex.quote(start_lock_path)}; '
        f'if flock -x 8; then current=$(cat {shlex.quote(os.path.join(active_path, "job_id"))} 2>/dev/null || true); '
        f'if [ "$current" = {shlex.quote(job_id)} ]; then rm -f {shlex.quote(pid_path)} '
        f'{shlex.quote(os.path.join(active_path, "job_id"))} {shlex.quote(os.path.join(active_path, "created"))}; '
        f'rmdir {shlex.quote(active_path)} 2>/dev/null || true; fi; fi; trap - EXIT; exit "$rc"'
    )
    runner = (
        f'JOB_ID={shlex.quote(job_id)}; START_TIME=$(awk \'{{print $22}}\' "/proc/$$/stat" 2>/dev/null || true); '
        f'if [[ "$START_TIME" =~ ^[1-9][0-9]*$ ]]; then printf "%s %s %s\\n" "$JOB_ID" "$$" "$START_TIME"; '
        f'else printf "%s %s\\n" "$JOB_ID" "$$"; fi > {shlex.quote(pid_path)}; '
        f'trap {shlex.quote(cleanup)} EXIT; '
        f'cd {shlex.quote(lldpq_dir)} || {{ echo "ERROR: LLDPq directory is unavailable" >> {shlex.quote(log_path)}; '
        f'printf "__LLDPQ_DONE__:10\\n" >> {shlex.quote(log_path)}; exit 10; }}; '
        f'/usr/local/bin/lldpq - >> {shlex.quote(log_path)} 2>&1; '
        f'rc=$?; printf "__LLDPQ_DONE__:%s\\n" "$rc" >> {shlex.quote(log_path)}; '
        f'exit "$rc"'
    )
    try:
        launch = f'nohup setsid bash -c {shlex.quote(runner)} >/dev/null 2>&1 &'
        launcher = subprocess.Popen(['sudo', '-u', lldpq_user, 'bash', '-c', launch],
                                    start_new_session=True, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            launcher_rc = launcher.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            launcher_rc = None
        if launcher_rc not in (None, 0):
            release_background_job(state_dir, 'run', job_id)
            print(json.dumps({'success': False, 'error': 'Detached LLDPq launch failed immediately'}))
            sys.exit(0)
        print(json.dumps({'success': True, 'message': 'LLDPq run started', 'job_id': job_id}))
    except Exception as e:
        release_background_job(state_dir, 'run', job_id)
        print(json.dumps({'success': False, 'error': str(e)}))
    sys.exit(0)

# ─── Action: Tail the run log started by action=run ───
if action == 'run-log':
    log_path = os.path.join(lldpq_dir, '.run.log')
    state_dir = os.path.join(os.path.expanduser('~' + lldpq_user), '.lldpq-state')
    pid_path = os.path.join(state_dir, 'run.pid')
    active_path = os.path.join(state_dir, 'run.active')
    content = ''
    try:
        r = subprocess.run(['sudo', '-u', lldpq_user, 'cat', log_path],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            content = r.stdout
    except Exception:
        content = ''
    display, raw_done, exit_code, ok, log_job_id = parse_completion_log(content)
    status = background_job_status(state_dir, 'run', raw_done, log_job_id)
    print(json.dumps({'success': True, 'done': status['done'],
                      'ok': ok and status['done'],
                      'running': status['running'],
                      'pid_recorded': status['pid_recorded'],
                      'job_id': status['job_id'],
                      'stale_reservation': status['stale_reservation'],
                      'exit_code': exit_code if status['done'] else None,
                      'log': display}))
    sys.exit(0)

# ─── Action: Ansible integration status (current dir, enabled?, auto-detected candidates) ───
if action == 'get-ansible':
    conf = read_conf()
    raw = conf.get('ANSIBLE_DIR', '')
    editor_raw = conf.get('EDITOR_ROOT', raw)
    disabled = (raw == '' or raw == 'NoNe')
    path = '' if disabled else raw
    warnings = []
    exists = bool(path) and os.path.isdir(path) and os.path.isdir(os.path.join(path, 'inventory'))
    inventory_file = ''
    if exists:
        for candidate in ('inventory.ini', 'hosts'):
            candidate_path = os.path.join(path, 'inventory', candidate)
            if os.path.isfile(candidate_path):
                inventory_file = candidate_path
                break
        if not inventory_file:
            warnings.append('inventory/ exists but inventory.ini or hosts was not found')
        if not os.access(path, os.R_OK | os.X_OK):
            warnings.append('The web service cannot read/traverse this directory; adjust group ACLs manually')
        if editor_raw not in (raw, '', 'NoNe'):
            warnings.append('EDITOR_ROOT differs from ANSIBLE_DIR; save this step to synchronize them')
        if not os.path.isdir(os.path.join(path, 'playbooks')):
            warnings.append('playbooks/ was not found; editor browsing may work but playbook actions will not')
    home = os.path.expanduser('~' + lldpq_user)
    candidates = []
    try:
        for name in sorted(os.listdir(home)):
            d = os.path.join(home, name)
            if os.path.isdir(os.path.join(d, 'inventory')) and os.path.isdir(os.path.join(d, 'playbooks')):
                candidates.append(d)
    except Exception:
        pass
    ready = disabled or (exists and bool(inventory_file) and not any('cannot read' in w for w in warnings))
    print(json.dumps({'success': True, 'disabled': disabled, 'path': path,
                      'editor_root': '' if editor_raw == 'NoNe' else editor_raw,
                      'exists': exists, 'ready': ready, 'warnings': warnings,
                      'inventory_file': inventory_file, 'candidates': candidates}))
    sys.exit(0)

# ─── Action: enable/point/disable Ansible integration (writes ANSIBLE_DIR, NoNe = off) ───
if action == 'set-ansible':
    disable = post_data.get('disable', False)
    if not isinstance(disable, bool):
        print(json.dumps({'success': False, 'error': 'disable must be true or false'}))
        sys.exit(0)
    raw_val = post_data.get('ansible_dir', '')
    if not isinstance(raw_val, str):
        print(json.dumps({'success': False, 'error': 'ansible_dir must be a string'}))
        sys.exit(0)
    val = raw_val.strip()
    if disable or not val:
        new_val = 'NoNe'
    else:
        if (len(val) > 4096 or not os.path.isabs(val)
                or any(char in val for char in ('\x00', '\r', '\n'))):
            print(json.dumps({'success': False, 'error': 'Ansible directory must be a safe absolute path'}))
            sys.exit(0)
        val = os.path.realpath(val)
        if not (os.path.isdir(val) and os.path.isdir(os.path.join(val, 'inventory'))):
            print(json.dumps({'success': False, 'error': 'Directory not found or missing an inventory/ folder: ' + val}))
            sys.exit(0)
        new_val = val
    if write_conf({'ANSIBLE_DIR': new_val, 'EDITOR_ROOT': new_val}):
        warnings = []
        ready = True
        if new_val != 'NoNe':
            inv = os.path.join(new_val, 'inventory')
            if not any(os.path.isfile(os.path.join(inv, name)) for name in ('inventory.ini', 'hosts')):
                warnings.append('Saved, but inventory/inventory.ini or inventory/hosts is missing')
                ready = False
            if not os.access(new_val, os.R_OK | os.X_OK):
                warnings.append('Saved, but the web service cannot read/traverse this directory; grant an appropriate group ACL')
                ready = False
            if not os.path.isdir(os.path.join(new_val, 'playbooks')):
                warnings.append('playbooks/ is missing; playbook actions will remain unavailable')
        print(json.dumps({'success': True, 'disabled': new_val == 'NoNe',
                          'path': '' if new_val == 'NoNe' else new_val,
                          'editor_root': '' if new_val == 'NoNe' else new_val,
                          'ready': ready, 'warnings': warnings}))
    else:
        print(json.dumps({'success': False, 'error': 'Failed to write config'}))
    sys.exit(0)

# ─── Action: read collection parallelism ───
if action == 'get-parallel':
    conf = read_conf()
    def _pint(key, default):
        try:
            return int(conf.get(key, default))
        except Exception:
            return default
    print(json.dumps({'success': True,
                      'monitor': _pint('MONITOR_MAX_PARALLEL', 100),
                      'lldp': _pint('LLDP_MAX_PARALLEL', 100),
                      'assets': _pint('ASSETS_MAX_PARALLEL', 100),
                      'getconfigs': _pint('GET_CONFIGS_MAX_PARALLEL', 100)}))
    sys.exit(0)

# ─── Action: set collection parallelism (presets only) ───
if action == 'set-parallel':
    ALLOWED = {50, 100, 150, 200, 250, 300, 500}
    keymap = {'monitor': 'MONITOR_MAX_PARALLEL', 'lldp': 'LLDP_MAX_PARALLEL',
              'assets': 'ASSETS_MAX_PARALLEL', 'getconfigs': 'GET_CONFIGS_MAX_PARALLEL'}
    pairs = {}
    for fk, ck in keymap.items():
        try:
            v = int(post_data.get(fk))
        except Exception:
            print(json.dumps({'success': False, 'error': 'Invalid value for ' + fk}))
            sys.exit(0)
        if v not in ALLOWED:
            print(json.dumps({'success': False, 'error': 'Unsupported value for ' + fk}))
            sys.exit(0)
        pairs[ck] = v
    if write_conf(pairs):
        print(json.dumps({'success': True}))
    else:
        print(json.dumps({'success': False, 'error': 'Failed to write config'}))
    sys.exit(0)

# ─── Action: environment info (is this running inside Docker?) ───
if action == 'env':
    print(json.dumps({'success': True, 'docker': os.path.exists('/.dockerenv')}))
    sys.exit(0)

# ─── Action: Update LLDPq (git pull + ./install.sh -y [--backup]) into a tailable log ───
if action == 'update':
    # Docker: a container can't replace its own image. Update is a host operation
    # (docker load + docker compose up); refuse here and let the UI show the host command.
    if os.path.exists('/.dockerenv'):
        print(json.dumps({'success': False, 'docker': True,
                          'error': 'Docker deployment: update on the host (docker load + docker compose up). See the instructions on this page.'}))
        sys.exit(0)
    backup = post_data.get('backup', False)
    if not isinstance(backup, bool):
        print(json.dumps({'success': False, 'error': 'backup must be true or false'}))
        sys.exit(0)
    url = 'https://github.com/aliaydemir/lldpq-src.git'
    # Stage the runner + log in ~/.lldpq-state, NOT inside lldpq_dir: install.sh wipes/
    # replaces the lldpq dir during an update (that's why it preserves data), which would
    # delete the log mid-run. A dedicated hidden dir in HOME survives the install and keeps
    # the home directory tidy.
    home_dir = os.path.expanduser('~' + lldpq_user)
    state_dir = os.path.join(home_dir, '.lldpq-state')
    try:
        prepared = subprocess.run(
            ['sudo', '-u', lldpq_user, 'mkdir', '-p', state_dir],
            capture_output=True, text=True, timeout=10,
        )
        if prepared.returncode != 0:
            raise RuntimeError('Could not prepare the update state directory')
    except Exception as exc:
        print(json.dumps({'success': False, 'error': str(exc)[:200]}))
        sys.exit(0)
    script_path = os.path.join(state_dir, 'update-run.sh')
    log_path = os.path.join(state_dir, 'update.log')
    try:
        with setup_job_start_guard():
            job_id, job_error = reserve_background_job(state_dir, 'update', log_path)
    except Exception as exc:
        print(json.dumps({'success': False, 'error': 'Could not reserve the update: ' + str(exc)[:160]}))
        sys.exit(0)
    if job_error:
        print(json.dumps({'success': False, 'conflict': True, 'error': job_error}))
        sys.exit(0)
    pid_path = os.path.join(state_dir, 'update.pid')
    active_path = os.path.join(state_dir, 'update.active')
    SCRIPT = '''#!/usr/bin/env bash
ACTIVE="__ACTIVE__"
PIDFILE="__PID__"
JOB_ID="__JOB__"
START_TIME=$(awk '{print $22}' "/proc/$$/stat" 2>/dev/null || true)
if [[ "$START_TIME" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s %s %s\n' "$JOB_ID" "$$" "$START_TIME" > "$PIDFILE"
else
    printf '%s %s\n' "$JOB_ID" "$$" > "$PIDFILE"
fi
cleanup_update_job() { rc=$?; exec 8>"${ACTIVE%.active}.start.lock"; if flock -x 8; then current=$(cat "$ACTIVE/job_id" 2>/dev/null || true); if [ "$current" = "$JOB_ID" ]; then rm -f "$PIDFILE" "$ACTIVE/job_id" "$ACTIVE/created"; rmdir "$ACTIVE" 2>/dev/null || true; fi; fi; trap - EXIT; exit "$rc"; }
trap cleanup_update_job EXIT
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi
SRC="${LLDPQ_SRC:-}"
HOMESRC="$HOME/lldpq-src"
URL="__URL__"
LOG="__LOG__"
: # log already initialized with the job marker by the reservation transaction
(
  echo "=== LLDPq Update $(date) ==="
  if [ -n "$SRC" ] && [ -d "$SRC/.git" ]; then
    cd "$SRC" || { echo "ERROR: cannot enter source repo: $SRC"; exit 10; }
  elif [ -d "$HOMESRC/.git" ]; then
    cd "$HOMESRC" || { echo "ERROR: cannot enter source repo: $HOMESRC"; exit 10; }
  else
    echo "Source repo not found (LLDPQ_SRC=$SRC); cloning $URL -> $HOMESRC"
    rm -rf "$HOMESRC"
    git clone "$URL" "$HOMESRC" || { echo "ERROR: git clone failed"; exit 11; }
    cd "$HOMESRC" || { echo "ERROR: cannot enter cloned source repo"; exit 10; }
  fi
  echo "--- git pull (in $(pwd)) ---"
  GIT_TERMINAL_PROMPT=0 timeout 120 git pull 2>&1
  git_rc=$?
  if [ "$git_rc" -ne 0 ]; then
    echo "ERROR: git pull failed (exit $git_rc); update stopped before install"
    exit "$git_rc"
  fi
  echo "--- ./install.sh -y __BACKUP__ ---"
  ./install.sh -y __BACKUP__ 2>&1
  install_rc=$?
  echo "--- install finished (exit $install_rc) ---"
  exit "$install_rc"
) >> "$LOG" 2>&1
rc=$?
printf '__LLDPQ_DONE__:%s\n' "$rc" >> "$LOG"
exit "$rc"
'''
    script = (SCRIPT.replace('__URL__', url)
              .replace('__BACKUP__', '--backup' if backup else '')
              .replace('__LOG__', log_path)
              .replace('__ACTIVE__', active_path)
              .replace('__PID__', pid_path)
              .replace('__JOB__', job_id))
    try:
        w = subprocess.run(['sudo', '-u', lldpq_user, 'tee', script_path],
                           input=script, capture_output=True, text=True, timeout=10)
        if w.returncode != 0:
            release_background_job(state_dir, 'update', job_id)
            print(json.dumps({'success': False, 'error': 'Could not stage update script'}))
            sys.exit(0)
        # Run the update in its OWN systemd transient unit (separate cgroup). install.sh
        # restarts fcgiwrap, and systemd kills the fcgiwrap.service cgroup on restart — a
        # plain nohup/setsid child stays in that cgroup (setsid changes the session, not the
        # cgroup) and gets killed mid-update. A transient unit is cgroup-independent and
        # survives. Fall back to nohup/setsid if systemd-run is unavailable.
        launch = ('if sudo systemd-run --no-block --collect '
                  '--uid=' + shlex.quote(lldpq_user) + ' '
                  '--setenv=HOME=' + shlex.quote(home_dir) + ' '
                  '/bin/bash ' + shlex.quote(script_path) + ' 2>/dev/null; then :; '
                  'else nohup setsid /bin/bash ' + shlex.quote(script_path) + ' >/dev/null 2>&1 & fi')
        launcher = subprocess.Popen(['sudo', '-u', lldpq_user, 'bash', '-c', launch],
                                    start_new_session=True, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            launcher_rc = launcher.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            launcher_rc = None
        if launcher_rc not in (None, 0):
            release_background_job(state_dir, 'update', job_id)
            print(json.dumps({'success': False, 'error': 'Detached update launch failed immediately'}))
            sys.exit(0)
        print(json.dumps({'success': True, 'message': 'Update started', 'job_id': job_id}))
    except Exception as e:
        release_background_job(state_dir, 'update', job_id)
        print(json.dumps({'success': False, 'error': str(e)}))
    sys.exit(0)

# ─── Action: Offline Update (apply a source tarball already on the host; no network/GitHub) ───
if action == 'update-offline':
    raw_tarball = post_data.get('path') or '/tmp/lldpq-src.tar.gz'
    if not isinstance(raw_tarball, str):
        print(json.dumps({'success': False, 'error': 'Offline update path must be a string'}))
        sys.exit(0)
    tarball = raw_tarball.strip()
    # Docker: a container can't replace its own image — update is a host operation.
    if os.path.exists('/.dockerenv'):
        cleanup_uploaded_tarball(tarball)
        print(json.dumps({'success': False, 'docker': True,
                          'error': 'Docker deployment: update on the host (docker load + docker compose up). See the instructions on this page.'}))
        sys.exit(0)
    backup = post_data.get('backup', False)
    if not isinstance(backup, bool):
        cleanup_uploaded_tarball(tarball)
        print(json.dumps({'success': False, 'error': 'backup must be true or false'}))
        sys.exit(0)
    # Strict path: absolute, no traversal, no shell metacharacters (it is substituted into the
    # runner script below, so this also prevents shell injection).
    if not re.match(r'^/[A-Za-z0-9._/-]+$', tarball) or '..' in tarball:
        cleanup_uploaded_tarball(tarball)
        print(json.dumps({'success': False, 'error': 'Enter a simple absolute path like /tmp/lldpq-src.tar.gz (letters, digits, . _ - / only).'}))
        sys.exit(0)
    home_dir = os.path.expanduser('~' + lldpq_user)
    state_dir = os.path.join(home_dir, '.lldpq-state')
    try:
        prepared = subprocess.run(
            ['sudo', '-u', lldpq_user, 'mkdir', '-p', state_dir],
            capture_output=True, text=True, timeout=10,
        )
        if prepared.returncode != 0:
            raise RuntimeError('Could not prepare the offline update state directory')
    except Exception as exc:
        cleanup_uploaded_tarball(tarball)
        print(json.dumps({'success': False, 'error': str(exc)[:200]}))
        sys.exit(0)
    script_path = os.path.join(state_dir, 'update-run.sh')
    log_path = os.path.join(state_dir, 'update.log')
    try:
        with setup_job_start_guard():
            job_id, job_error = reserve_background_job(state_dir, 'update', log_path)
    except Exception as exc:
        cleanup_uploaded_tarball(tarball)
        print(json.dumps({'success': False, 'error': 'Could not reserve the offline update: ' + str(exc)[:160]}))
        sys.exit(0)
    if job_error:
        cleanup_uploaded_tarball(tarball)
        print(json.dumps({'success': False, 'conflict': True, 'error': job_error}))
        sys.exit(0)
    pid_path = os.path.join(state_dir, 'update.pid')
    active_path = os.path.join(state_dir, 'update.active')
    # Same log + systemd-run isolation as action=update, so the existing update-log polling
    # and the UI live view work unchanged. The only difference is the source: extract a local
    # tarball instead of git pull/clone, then run install.sh -y (update mode = offline-safe:
    # it skips apt/pip/Monaco which only run on a fresh install).
    SCRIPT = '''#!/usr/bin/env bash
ACTIVE="__ACTIVE__"
PIDFILE="__PID__"
JOB_ID="__JOB__"
START_TIME=$(awk '{print $22}' "/proc/$$/stat" 2>/dev/null || true)
if [[ "$START_TIME" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s %s %s\n' "$JOB_ID" "$$" "$START_TIME" > "$PIDFILE"
else
    printf '%s %s\n' "$JOB_ID" "$$" > "$PIDFILE"
fi
cleanup_update_job() { rc=$?; case "${TARBALL:-}" in /tmp/lldpq-upload-src.*.tar.gz) rm -f -- "$TARBALL";; esac; exec 8>"${ACTIVE%.active}.start.lock"; if flock -x 8; then current=$(cat "$ACTIVE/job_id" 2>/dev/null || true); if [ "$current" = "$JOB_ID" ]; then rm -f "$PIDFILE" "$ACTIVE/job_id" "$ACTIVE/created"; rmdir "$ACTIVE" 2>/dev/null || true; fi; fi; trap - EXIT; exit "$rc"; }
trap cleanup_update_job EXIT
TARBALL="__TARBALL__"
DEST="$HOME/lldpq-src"
LOG="__LOG__"
: # log already initialized with the job marker by the reservation transaction
(
  TMP=""
  trap '[ -z "$TMP" ] || rm -rf "$TMP"' EXIT
  echo "=== LLDPq Offline Update $(date) ==="
  echo "--- tarball: $TARBALL ---"
  if [ ! -f "$TARBALL" ]; then echo "ERROR: tarball not found (or not readable by $(whoami)): $TARBALL"; exit 1; fi
  TMP="$(mktemp -d)"
  echo "--- validating and extracting safely ---"
  if ! python3 - "$TARBALL" "$TMP" <<'PYSAFE'
import os
import pathlib
import shutil
import sys
import tarfile

archive_path, destination = sys.argv[1:]
max_members = 100000
max_member_bytes = 256 * 1024 * 1024
max_total_bytes = 1024 * 1024 * 1024
seen = set()

def safe_parts(name):
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
        raise ValueError("archive contains an unsafe member name")
    path = pathlib.PurePosixPath(name)
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if path.is_absolute() or ".." in parts or not parts:
        raise ValueError("archive contains an unsafe member path: " + name[:160])
    if len(name) > 4096 or any(len(part.encode("utf-8")) > 255 for part in parts):
        raise ValueError("archive member path is too long")
    return parts

try:
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > max_members:
            raise ValueError("archive contains too many members")
        total = 0
        planned = []
        for member in members:
            if member.isdir() and member.name.rstrip("/") in ("", "."):
                continue
            parts = safe_parts(member.name)
            normalized = "/".join(parts)
            if normalized in seen:
                raise ValueError("archive contains duplicate member: " + normalized[:160])
            seen.add(normalized)
            if not (member.isdir() or member.isfile()):
                raise ValueError("archive links/devices are not allowed: " + normalized[:160])
            if member.size < 0 or member.size > max_member_bytes:
                raise ValueError("archive member is too large: " + normalized[:160])
            total += member.size
            if total > max_total_bytes:
                raise ValueError("expanded archive exceeds 1 GiB")
            planned.append((member, parts))

        root = os.path.realpath(destination)
        for member, parts in planned:
            target = os.path.join(root, *parts)
            parent = target if member.isdir() else os.path.dirname(target)
            os.makedirs(parent, mode=0o755, exist_ok=True)
            if os.path.commonpath((root, os.path.realpath(parent))) != root:
                raise ValueError("archive member escaped the extraction directory")
            if member.isdir():
                if not os.path.isdir(target):
                    raise ValueError("archive directory conflicts with a file")
                continue
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("archive member could not be read")
            try:
                with open(target, "xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                source.close()
            mode = member.mode & 0o777
            os.chmod(target, mode or 0o644)
except (OSError, tarfile.TarError, ValueError) as error:
    print("ERROR: safe archive extraction failed: " + str(error), file=sys.stderr)
    raise SystemExit(1)
PYSAFE
  then
    echo "ERROR: extract failed (invalid, unsafe, or over-sized .tar.gz)"
    exit 1
  fi
  INSTALLER="$(find "$TMP" -maxdepth 2 -name install.sh -type f 2>/dev/null | head -1)"
  if [ -z "$INSTALLER" ]; then echo "ERROR: install.sh not found inside the tarball"; exit 1; fi
  SRCDIR="$(dirname "$INSTALLER")"
  echo "--- source: $SRCDIR ---"
  if rm -rf "$DEST" && mkdir -p "$DEST" && cp -a "$SRCDIR/." "$DEST/"; then
    cd "$DEST" || { echo "ERROR: cannot enter staged source: $DEST"; exit 12; }
  else
    echo "(staging to $DEST failed; running from the extract dir)"
    cd "$SRCDIR" || { echo "ERROR: cannot enter extracted source: $SRCDIR"; exit 12; }
  fi
  chmod +x ./install.sh 2>/dev/null
  echo "--- ./install.sh -y __BACKUP__ (offline) ---"
  LLDPQ_OFFLINE_UPDATE=1 ./install.sh -y __BACKUP__ 2>&1
  install_rc=$?
  echo "--- install finished (exit $install_rc) ---"
  exit "$install_rc"
) >> "$LOG" 2>&1
rc=$?
printf '__LLDPQ_DONE__:%s\n' "$rc" >> "$LOG"
exit "$rc"
'''
    script = (SCRIPT.replace('__TARBALL__', tarball)
              .replace('__BACKUP__', '--backup' if backup else '')
              .replace('__LOG__', log_path)
              .replace('__ACTIVE__', active_path)
              .replace('__PID__', pid_path)
              .replace('__JOB__', job_id))
    try:
        w = subprocess.run(['sudo', '-u', lldpq_user, 'tee', script_path],
                           input=script, capture_output=True, text=True, timeout=10)
        if w.returncode != 0:
            release_background_job(state_dir, 'update', job_id)
            cleanup_uploaded_tarball(tarball)
            print(json.dumps({'success': False, 'error': 'Could not stage update script'}))
            sys.exit(0)
        launch = ('if sudo systemd-run --no-block --collect '
                  '--uid=' + shlex.quote(lldpq_user) + ' '
                  '--setenv=HOME=' + shlex.quote(home_dir) + ' '
                  '/bin/bash ' + shlex.quote(script_path) + ' 2>/dev/null; then :; '
                  'else nohup setsid /bin/bash ' + shlex.quote(script_path) + ' >/dev/null 2>&1 & fi')
        launcher = subprocess.Popen(['sudo', '-u', lldpq_user, 'bash', '-c', launch],
                                    start_new_session=True, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            launcher_rc = launcher.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            launcher_rc = None
        if launcher_rc not in (None, 0):
            release_background_job(state_dir, 'update', job_id)
            cleanup_uploaded_tarball(tarball)
            print(json.dumps({'success': False, 'error': 'Detached offline update launch failed immediately'}))
            sys.exit(0)
        print(json.dumps({'success': True, 'message': 'Offline update started', 'job_id': job_id}))
    except Exception as e:
        release_background_job(state_dir, 'update', job_id)
        cleanup_uploaded_tarball(tarball)
        print(json.dumps({'success': False, 'error': str(e)}))
    sys.exit(0)

# ─── Action: Tail the update log started by action=update ───
if action == 'update-log':
    state_dir = os.path.join(os.path.expanduser('~' + lldpq_user), '.lldpq-state')
    log_path = os.path.join(state_dir, 'update.log')
    active_path = os.path.join(state_dir, 'update.active')
    pid_path = os.path.join(state_dir, 'update.pid')
    content = ''
    try:
        r = subprocess.run(['sudo', '-u', lldpq_user, 'cat', log_path],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            content = r.stdout
    except Exception:
        content = ''
    display, raw_done, exit_code, ok, log_job_id = parse_completion_log(content)
    status = background_job_status(state_dir, 'update', raw_done, log_job_id)
    print(json.dumps({'success': True, 'done': status['done'],
                      'ok': ok and status['done'],
                      'running': status['running'], 'job_id': status['job_id'],
                      'pid_recorded': status['pid_recorded'],
                      'stale_reservation': status['stale_reservation'],
                      'exit_code': exit_code if status['done'] else None,
                      'log': display}))
    sys.exit(0)

# ─── Action: Read cron schedules for lldpq (auto-run) and get-conf (config collection) ───
if action == 'get-schedules':
    ensure_configuration_lock()
    cron_file = '/etc/cron.d/lldpq' if os.path.exists('/etc/cron.d/lldpq') else '/etc/crontab'
    lldpq_expr = ''
    getconf_expr = ''
    try:
        with open(cron_file) as f:
            for line in f:
                if line.lstrip().startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 7 and parts[6] == '/usr/local/bin/lldpq':
                    lldpq_expr = ' '.join(parts[:5])
                elif len(parts) >= 7 and parts[6] == '/usr/local/bin/get-conf':
                    getconf_expr = ' '.join(parts[:5])
    except Exception:
        pass

    def _mins(e):
        m = re.match(r'^\*/(\d+) \* \* \* \*$', e)
        return int(m.group(1)) if m else None

    def _hours(e):
        m = re.match(r'^0 \*/(\d+) \* \* \*$', e)
        if m:
            return int(m.group(1))
        return 24 if e == '0 0 * * *' else None

    print(json.dumps({'success': True, 'cron_file': cron_file,
                      'lldpq_minutes': _mins(lldpq_expr), 'lldpq_cron': lldpq_expr,
                      'getconf_hours': _hours(getconf_expr), 'getconf_cron': getconf_expr}))
    sys.exit(0)

# ─── Action: Change cron schedules (presets only) + persist to lldpq.conf ───
if action == 'set-schedules':
    ensure_configuration_lock()
    LLDPQ_PRESETS = {5: '*/5 * * * *', 10: '*/10 * * * *', 15: '*/15 * * * *', 20: '*/20 * * * *', 30: '*/30 * * * *'}
    GETCONF_PRESETS = {6: '0 */6 * * *', 12: '0 */12 * * *', 24: '0 0 * * *'}
    try:
        mins = int(post_data.get('lldpq_minutes'))
        hours = int(post_data.get('getconf_hours'))
    except Exception:
        print(json.dumps({'success': False, 'error': 'Invalid interval'}))
        sys.exit(0)
    if mins not in LLDPQ_PRESETS or hours not in GETCONF_PRESETS:
        print(json.dumps({'success': False, 'error': 'Unsupported interval'}))
        sys.exit(0)
    lldpq_cron = LLDPQ_PRESETS[mins]
    getconf_cron = GETCONF_PRESETS[hours]
    if not valid_cron_schedule(lldpq_cron) or not valid_cron_schedule(getconf_cron):
        print(json.dumps({'success': False, 'error': 'Generated cron schedule failed validation'}))
        sys.exit(0)
    cron_file = '/etc/cron.d/lldpq' if os.path.exists('/etc/cron.d/lldpq') else '/etc/crontab'
    try:
        with open(cron_file) as f:
            orig = f.readlines()
    except Exception as e:
        print(json.dumps({'success': False, 'error': 'Cannot read ' + cron_file + ': ' + str(e)}))
        sys.exit(0)
    # Rebuild only the lldpq + get-conf lines (preserve every other line byte-for-byte).
    out = []
    found_lldpq = False
    found_getconf = False
    for line in orig:
        parts = line.split()
        if (not line.lstrip().startswith('#')) and len(parts) >= 7 and parts[6] == '/usr/local/bin/lldpq':
            out.append(lldpq_cron + ' ' + ' '.join(parts[5:]) + '\n')
            found_lldpq = True
        elif (not line.lstrip().startswith('#')) and len(parts) >= 7 and parts[6] == '/usr/local/bin/get-conf':
            out.append(getconf_cron + ' ' + ' '.join(parts[5:]) + '\n')
            found_getconf = True
        else:
            out.append(line)
    if not found_lldpq or not found_getconf:
        missing = []
        if not found_lldpq:
            missing.append('/usr/local/bin/lldpq')
        if not found_getconf:
            missing.append('/usr/local/bin/get-conf')
        print(json.dumps({
            'success': False,
            'error': 'Required cron entry is missing: ' + ', '.join(missing) +
                     '. Run install.sh to repair the schedule file.'
        }))
        sys.exit(0)
    new_content = ''.join(out)
    try:
        if not install_text_as_root(new_content, cron_file, '.cron.setup.tmp', '644'):
            rolled_back = install_text_as_root(
                ''.join(orig), cron_file, '.cron.setup.rollback.tmp', '644'
            )
            error = ('Could not update cron file; original cron was restored'
                     if rolled_back else
                     'Could not update cron file and automatic cron rollback failed')
            print(json.dumps({'success': False, 'error': error}))
            sys.exit(0)
        if not write_conf({
            'LLDPQ_CRON': '"' + lldpq_cron + '"',
            'GETCONF_CRON': '"' + getconf_cron + '"',
        }):
            # Keep the live cron and persisted configuration in sync.
            rolled_back = install_text_as_root(
                ''.join(orig), cron_file, '.cron.rollback.tmp', '644'
            )
            error = ('Cron updated but config persistence failed; cron was rolled back'
                     if rolled_back else
                     'Cron updated but config persistence failed, and automatic cron rollback failed')
            print(json.dumps({'success': False, 'error': error}))
            sys.exit(0)
        print(json.dumps({'success': True, 'lldpq_cron': lldpq_cron, 'getconf_cron': getconf_cron}))
    except Exception as e:
        print(json.dumps({'success': False, 'error': str(e)}))
    sys.exit(0)

# ─── Action: Read notifications.yaml (Slack/alerting config) ───
if action == 'get-notifications':
    import yaml
    notif_yaml = os.path.join(lldpq_dir, 'notifications.yaml')
    snapshot = service_safe_read(notif_yaml)
    if not snapshot.get('success'):
        print(json.dumps({'success': False,
                          'error': 'Cannot read notifications.yaml: ' +
                                   str(snapshot.get('error', 'safe read failed'))[:300]}))
        sys.exit(0)
    exists = bool(snapshot.get('exists'))
    cfg = {}
    revision = snapshot['revision']
    if exists:
        try:
            cfg = yaml.safe_load(snapshot.get('content', '')) or {}
        except Exception as e:
            print(json.dumps({'success': False, 'error': 'Cannot parse notifications.yaml: ' + str(e)}))
            sys.exit(0)
    if not isinstance(cfg, dict):
        print(json.dumps({'success': False, 'error': 'notifications.yaml must contain a mapping'}))
        sys.exit(0)
    for section in ('notifications', 'thresholds', 'alert_types', 'alert_strategy', 'frequency'):
        if section in cfg and cfg[section] is not None and not isinstance(cfg[section], dict):
            print(json.dumps({'success': False, 'error': section + ' must be a mapping in notifications.yaml'}))
            sys.exit(0)
    n = cfg.get('notifications') or {}
    if 'slack' in n and n['slack'] is not None and not isinstance(n['slack'], dict):
        print(json.dumps({'success': False, 'error': 'notifications.slack must be a mapping'}))
        sys.exit(0)
    slack = n.get('slack') or {}
    thr = cfg.get('thresholds') or {}
    for subsection in ('network', 'hardware', 'system'):
        if subsection in thr and thr[subsection] is not None and not isinstance(thr[subsection], dict):
            print(json.dumps({'success': False, 'error': 'thresholds.' + subsection + ' must be a mapping'}))
            sys.exit(0)
    net = thr.get('network') or {}
    hw = thr.get('hardware') or {}
    sysd = thr.get('system') or {}
    at = cfg.get('alert_types') or {}
    strat = cfg.get('alert_strategy') or {}
    freq = cfg.get('frequency') or {}
    out = {
        'enabled': bool(n.get('enabled', False)),
        'server_url': n.get('server_url', '') or '',
        'slack_enabled': bool(slack.get('enabled', False)),
        'webhook': slack.get('webhook', '') or '',
        'channel': slack.get('channel', '#lldpq') or '#lldpq',
        'mode': strat.get('mode', 'summary') or 'summary',
        'min_interval': freq.get('min_interval_minutes', 30),
        't_hardware': bool(at.get('hardware_alerts', True)),
        't_network': bool(at.get('network_alerts', True)),
        't_system': bool(at.get('system_alerts', True)),
        't_topology': bool(at.get('topology_alerts', True)),
        't_log': bool(at.get('log_alerts', True)),
        'thresholds': {
            'bgp': net.get('bgp_down_minutes', 5),
            'flap_warn': net.get('link_flaps_per_hour', 10),
            'flap_crit': net.get('link_flaps_critical', 20),
            'optical': net.get('optical_power_margin', 3),
            'cpu': hw.get('cpu_temp_critical', 85),
            'asic': hw.get('asic_temp_critical', 90),
            'disk': sysd.get('disk_usage_critical', 90),
        },
    }
    print(json.dumps({'success': True, 'exists': exists, 'notifications': out,
                      'revision': revision}))
    sys.exit(0)

# ─── Action: Write notifications.yaml (preserve unrelated keys; UI-managed) ───
if action == 'set-notifications':
    notif_yaml = os.path.join(lldpq_dir, 'notifications.yaml')
    expected_revision = post_data.get('expected_revision', post_data.get('revision'))
    if expected_revision is not None and not isinstance(expected_revision, str):
        print(json.dumps({'success': False, 'error': 'revision must be a string'}))
        sys.exit(0)
    payload = dict(post_data)
    payload.pop('action', None)
    payload.pop('revision', None)
    payload.pop('expected_revision', None)
    response = service_atomic_write(
        'save-notifications', notif_yaml, json.dumps(payload),
        expected_revision=expected_revision,
    )
    print(json.dumps(response))
    sys.exit(0)

# ─── Action: Send a test Slack message to confirm the webhook works ───
if action == 'test-alert':
    webhook = str(post_data.get('webhook', '') or '').strip()
    channel = str(post_data.get('channel', '') or '').strip()
    if not webhook:
        try:
            import yaml
            notification_snapshot = service_safe_read(
                os.path.join(lldpq_dir, 'notifications.yaml')
            )
            if not notification_snapshot.get('success'):
                raise RuntimeError(notification_snapshot.get('error', 'safe read failed'))
            c = yaml.safe_load(notification_snapshot.get('content', '')) or {}
            webhook = (((c.get('notifications') or {}).get('slack') or {}).get('webhook') or '').strip()
        except Exception:
            pass
    if not webhook.startswith('https://hooks.slack.com/'):
        print(json.dumps({'success': False, 'error': 'Enter a valid Slack webhook URL (https://hooks.slack.com/…) first.'}))
        sys.exit(0)
    import urllib.request
    payload = {'text': ':white_check_mark: LLDPq test alert — your Slack webhook is working.'}
    if channel:
        payload['channel'] = channel
    try:
        req = urllib.request.Request(webhook, data=json.dumps(payload).encode(),
                                     headers={'Content-Type': 'application/json'})
        resp = urllib.request.urlopen(req, timeout=10)
        code = resp.getcode()
        if code == 200:
            print(json.dumps({'success': True}))
        else:
            print(json.dumps({'success': False, 'error': 'Slack returned HTTP ' + str(code)}))
    except Exception as e:
        print(json.dumps({'success': False, 'error': 'Send failed: ' + str(e)[:200]}))
    sys.exit(0)

# ─── Action: Export config bundle (inventory/tracking/topology/notifications) ───
if action == 'backup-export':
    import base64, importlib.util, io, tarfile, time as _t
    include_key = post_data.get('include_key', False)
    if not isinstance(include_key, bool):
        print(json.dumps({'success': False, 'error': 'include_key must be true or false'}))
        sys.exit(0)
    wanted = [('devices.yaml', lldpq_dir), ('tracking.yaml', lldpq_dir),
              ('topology.dot', lldpq_dir),
              ('topology_config.yaml', lldpq_dir), ('notifications.yaml', lldpq_dir),
              ('display-aliases.json', web_root)]
    buf = io.BytesIO()
    added = []
    has_key = False
    sensitive_files = []
    try:
        ensure_backup_locks()
        if include_key:
            ensure_ssh_key_lock()
        backup_tools = load_backup_import_helper('lldpq_backup_tools')
        # Native and Docker installs intentionally expose several config files
        # through symlinks. Read their resolved bytes under a managed root and
        # create regular tar members; path-based archive insertion would preserve
        # the link itself and produce a bundle the fail-closed importer rejects.
        config_files = backup_tools.collect_managed_config_files(
            wanted, (lldpq_dir, web_root)
        )
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for fn, content in config_files:
                # Never return a successful bundle that this same release will
                # reject during restore. This catches hand-edited/legacy drift
                # across every managed config, not only display aliases.
                backup_tools.validate_config_for_bundle(
                    fn, content, lldpq_dir=lldpq_dir
                )
                if fn == 'display-aliases.json':
                    try:
                        aliases_value = json.loads(content.decode('utf-8'))
                        aliases_value = backup_tools.validate_display_aliases(aliases_value)
                        content = (json.dumps(
                            aliases_value, indent=2, ensure_ascii=False
                        ) + '\n').encode('utf-8')
                    except Exception as exc:
                        raise RuntimeError('display-aliases.json is invalid: ' + str(exc)) from exc
                backup_tools.add_regular_tar_member(tar, fn, content, mode=0o600)
                added.append(fn)
                if fn == 'notifications.yaml':
                    try:
                        import yaml
                        notification_cfg = yaml.safe_load(content.decode('utf-8')) or {}
                        webhook = (((notification_cfg.get('notifications') or {}).get('slack') or {}).get('webhook') or '')
                        if webhook:
                            sensitive_files.append('notifications.yaml (Slack webhook)')
                    except Exception:
                        # The importer validates this file on restore.  If it is
                        # malformed, conservatively mark it sensitive here.
                        sensitive_files.append('notifications.yaml (unparsed)')
            # Collector SSH key (private + public). Opt-in — makes the bundle SECRET, but lets a
            # restore reach the switches immediately (true "move to another host" bundle).
            if include_key:
                for key_name in ('id_ed25519', 'id_rsa'):
                    kp = os.path.expanduser('~%s/.ssh/%s' % (lldpq_user, key_name))
                    r = subprocess.run(['sudo', '-u', lldpq_user, 'cat', kp], capture_output=True, timeout=5)
                    if r.returncode == 0 and b'PRIVATE KEY' in r.stdout:
                        derived = subprocess.run(
                            ['sudo', '-u', lldpq_user, 'ssh-keygen', '-y', '-f', kp],
                            capture_output=True, timeout=10
                        )
                        if derived.returncode != 0 or not derived.stdout.strip():
                            raise RuntimeError('Could not validate/derive public key for ' + key_name)
                        backup_tools.add_regular_tar_member(
                            tar, 'ssh/%s' % key_name, r.stdout, mode=0o600
                        )
                        added.append('ssh/%s' % key_name); has_key = True
                        sensitive_files.append('ssh/%s (private key)' % key_name)
                        # Derive instead of trusting a possibly missing/stale .pub.
                        public_bytes = derived.stdout.strip() + b'\n'
                        backup_tools.add_regular_tar_member(
                            tar, 'ssh/%s.pub' % key_name, public_bytes, mode=0o644
                        )
                        added.append('ssh/%s.pub' % key_name)
                        break
            # Portable preferences from /etc/lldpq.conf: ONLY tunable knobs (schedules, parallelism,
            # toggles, AI provider/model). Deliberately excludes host paths/identity (LLDPQ_DIR,
            # LLDPQ_USER, WEB_ROOT, *_DIR, DHCP_*, DISCOVERY_RANGE) and secrets (AI_API_KEY).
            PREF_KEYS = LLDPQ_PREF_KEYS
            ensure_configuration_lock()
            try:
                conf_lines = open('/etc/lldpq.conf').read().splitlines()
            except Exception:
                conf_lines = []
            pref_lines = [s.strip() for s in conf_lines
                          if s.strip() and not s.strip().startswith('#') and '=' in s
                          and s.split('=', 1)[0].strip() in PREF_KEYS]
            if pref_lines:
                pdata = ('# LLDPq portable preferences — schedules / parallelism / toggles.\n'
                         '# No host paths, no secrets. Re-applied by key on restore.\n'
                         + '\n'.join(pref_lines) + '\n').encode()
                backup_tools.add_regular_tar_member(
                    tar, 'prefs/lldpq.conf', pdata, mode=0o600
                )
                added.append('prefs/lldpq.conf')
    except Exception as e:
        print(json.dumps({'success': False, 'error': 'Bundle failed: ' + str(e)}))
        sys.exit(0)
    if not added:
        print(json.dumps({'success': False, 'error': 'No config files found to back up.'}))
        sys.exit(0)
    name = ('lldpq-backup-%s.tar.gz' if has_key else 'lldpq-config-%s.tar.gz') % _t.strftime('%Y%m%d-%H%M%S')
    print(json.dumps({'success': True, 'filename': name, 'files': added, 'has_key': has_key,
                      'sensitive': bool(sensitive_files), 'sensitive_files': sensitive_files,
                      'data': base64.b64encode(buf.getvalue()).decode()}))
    sys.exit(0)

# ─── Action: Restore config bundle (upload) — only known config files, no path traversal ───
if action == 'backup-import':
    import importlib.util
    b64 = post_data.get('data', '')
    if not b64:
        print(json.dumps({'success': False, 'error': 'No file data'}))
        sys.exit(0)
    try:
        importer = load_backup_import_helper('lldpq_backup_import')
        result = importer.restore_bundle(
            b64, lldpq_user=lldpq_user, lldpq_dir=lldpq_dir, web_root=web_root,
            pref_keys=LLDPQ_PREF_KEYS, validate_cron=valid_cron_schedule,
            acquire_lock=ensure_backup_locks,
        )
    except Exception as exc:
        print(json.dumps({'success': False, 'error': 'Backup restore failed: ' + str(exc)[:300]}))
        sys.exit(0)
    print(json.dumps(result))
    sys.exit(0)

# ─── Action: Maintenance — disk usage + count of old update backups ───
if action == 'get-maintenance':
    def _run(cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return r.stdout.strip()
        except Exception:
            return ''
    mr = os.path.join(lldpq_dir, 'monitor-results')
    # monitor-results is group-readable by www-data ($USER:www-data, 775/664), so du runs directly
    # as the CGI user. (Going through `sudo -u LLDPQ_USER du` fails: du is not in the sudoers
    # whitelist, which only allows bash/ssh/tee/etc.)
    mon = _run(['du', '-sm', mr]) if os.path.isdir(mr) else ''
    mon_mb = int(mon.split()[0]) if mon and mon.split() and mon.split()[0].isdigit() else 0
    info = _run(['sudo', '-n', '-u', lldpq_user, '/usr/bin/bash', '-c',
                 'shopt -s nullglob; f=(); for d in ~/lldpq-backup-*; do '
                 '[ -d "$d" ] && [ -s "$d/COMPLETE" ] && f+=("$d"); done; '
                 'echo -n "${#f[@]} "; if [ ${#f[@]} -gt 0 ]; then '
                 'du -scm "${f[@]}" 2>/dev/null | tail -1 | cut -f1; else echo 0; fi'])
    parts = info.split()
    bk_count = int(parts[0]) if len(parts) >= 1 and parts[0].isdigit() else 0
    bk_mb = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    disk = _run(['bash', '-c', 'df -h ' + shlex.quote(lldpq_dir) +
                 " | tail -1 | awk '{print $4\" free of \"$2\" (\"$5\" used)\"}'"])
    print(json.dumps({'success': True, 'monitor_mb': mon_mb,
                      'backup_count': bk_count, 'backup_mb': bk_mb, 'disk': disk}))
    sys.exit(0)

# ─── Action: Purge old update backups (~/lldpq-backup-*) — safe, service-user owned only ───
if action == 'purge-data':
    if post_data.get('target') != 'update_backups':
        print(json.dumps({'success': False, 'error': 'Unknown purge target'}))
        sys.exit(0)
    r = subprocess.run(['sudo', '-n', '-u', lldpq_user, '/usr/bin/bash', '-c',
                        'set -o pipefail; state="$HOME/.lldpq-state"; if [ -d "$state/update.active" ]; then '
                        'echo "ACTIVE"; exit 75; fi; shopt -s nullglob; f=(); '
                        'for d in ~/lldpq-backup-*; do [ -d "$d" ] && [ -s "$d/COMPLETE" ] && f+=("$d"); done; '
                        'n=${#f[@]}; m=0; if [ $n -gt 0 ]; then '
                        'm=$(du -scm "${f[@]}" 2>/dev/null | tail -1 | cut -f1) || exit 2; '
                        'rm -rf -- "${f[@]}" || exit 3; fi; echo "$n ${m:-0}"'],
                       capture_output=True, text=True, timeout=120)
    if r.returncode == 75:
        print(json.dumps({'success': False, 'error': 'An update is active; completed backups were not removed.'}))
        sys.exit(0)
    if r.returncode != 0:
        print(json.dumps({'success': False, 'error': 'Backup purge failed: ' + (r.stderr or r.stdout or '').strip()[:200]}))
        sys.exit(0)
    parts = (r.stdout or '').split()
    n = int(parts[0]) if len(parts) >= 1 and parts[0].isdigit() else 0
    mb = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    print(json.dumps({'success': True, 'removed': n, 'freed_mb': mb,
                      'scope': 'completed_update_backups'}))
    sys.exit(0)

# ─── Action: Generate new key + distribute with password ───
password = post_data.get('password', '')
retry_devices = post_data.get('retry_devices', [])  # List of IPs for retry

if (not isinstance(password, str) or not password or len(password) > 1024
        or any(char in password for char in ('\x00', '\r', '\n'))):
    print(json.dumps({'success': False, 'error': 'Password is required'}))
    sys.exit(0)
if not isinstance(retry_devices, list) or any(not isinstance(value, str) for value in retry_devices):
    print(json.dumps({'success': False, 'error': 'retry_devices must be a list of device addresses'}))
    sys.exit(0)

try:
    ensure_ssh_key_lock()
except Exception as exc:
    print(json.dumps({'success': False, 'error': str(exc)}))
    sys.exit(0)

# Ensure SSH key exists
ssh_key_path, key_generated, key_error = ensure_ssh_key(lldpq_user)
if key_error:
    print(json.dumps({'success': False, 'error': f'SSH key error: {key_error}'}))
    sys.exit(0)

# Load devices
all_devices, load_error = load_devices(devices_yaml)
if load_error:
    print(json.dumps({'success': False, 'error': load_error}))
    sys.exit(0)

# Filter for retry if specified
if retry_devices:
    all_devices = [d for d in all_devices if d['ip'] in retry_devices]
    if not all_devices:
        print(json.dumps({'success': False, 'error': 'No matching devices for retry'}))
        sys.exit(0)

# Run setup for all devices in parallel
results = []
with ThreadPoolExecutor(max_workers=20) as executor:
    futures = {
        executor.submit(setup_device, device, password, ssh_key_path, lldpq_user): device
        for device in all_devices
    }
    for future in as_completed(futures):
        try:
            results.append(future.result())
        except Exception as e:
            device = futures[future]
            results.append({
                'hostname': device['hostname'],
                'ip': device['ip'],
                'username': device['username'],
                'send_key': 'fail',
                'sudo_fix': 'fail',
                'send_key_msg': str(e),
                'sudo_fix_msg': ''
            })

# Sort by hostname
results.sort(key=lambda r: r['hostname'])

# Summary
total = len(results)
send_key_ok = sum(1 for r in results if r['send_key'] in ('ok', 'already'))
sudo_fix_ok = sum(1 for r in results if r['sudo_fix'] == 'ok')
ready_ok = sum(1 for r in results
               if r['send_key'] in ('ok', 'already') and r['sudo_fix'] == 'ok')

print(json.dumps({
    'success': True,
    'key_generated': key_generated,
    'ssh_key': ssh_key_path,
    'total': total,
    'send_key_ok': send_key_ok,
    'sudo_fix_ok': sudo_fix_ok,
    'ready_ok': ready_ok,
    'all_ready': ready_ok == total,
    'results': results
}))
PYTHON
