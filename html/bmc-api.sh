#!/usr/bin/env bash
# BMC mapping editor and cached wiring results. GET never contacts switches.

json_bootstrap_error() {
    printf 'Status: 503 Service Unavailable\nContent-Type: application/json; charset=UTF-8\nCache-Control: no-store\n\n'
    printf '{"success":false,"error":"BMC runtime support is unavailable; complete or repair the installation"}\n'
    exit 0
}

AUTH_GUARD="$(dirname "$0")/auth-guard.sh"
[[ -r "$AUTH_GUARD" ]] || json_bootstrap_error
source "$AUTH_GUARD" || json_bootstrap_error
declare -F require_auth >/dev/null && declare -F require_admin >/dev/null || json_bootstrap_error
require_auth

ACTION=$(python3 -c 'import os,urllib.parse; print(urllib.parse.parse_qs(os.environ.get("QUERY_STRING", "")).get("action", ["results"])[0])') || json_bootstrap_error
[[ "$ACTION" != save ]] || require_admin

LLDPQ_CONFIG_HELPER="${LLDPQ_CONFIG_HELPER:-/usr/local/bin/lldpq-config}"
[[ -x "$LLDPQ_CONFIG_HELPER" ]] || json_bootstrap_error
if ! LLDPQ_CONFIG_ASSIGNMENTS=$("$LLDPQ_CONFIG_HELPER" --require-config --require-key LLDPQ_DIR 2>/dev/null); then
    json_bootstrap_error
fi
eval "$LLDPQ_CONFIG_ASSIGNMENTS" || json_bootstrap_error
unset LLDPQ_CONFIG_ASSIGNMENTS
WEB_ROOT="${WEB_ROOT:-$(cd "$(dirname "$0")" && pwd)}"
export LLDPQ_DIR WEB_ROOT

python3 /dev/fd/3 "$ACTION" 3<<'PYTHON'
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import sys


def respond(status, payload):
    print('Status: ' + status)
    print('Content-Type: application/json; charset=UTF-8')
    print('Cache-Control: no-store, no-cache, must-revalidate, max-age=0')
    print()
    print(json.dumps(payload, ensure_ascii=True, allow_nan=False))
    raise SystemExit(0)


root = Path(os.environ['LLDPQ_DIR'])
sys.path.insert(0, str(root))
try:
    from bmc_config import (BMCConfigError, BMCConflictError, BMCValidationError,
                            get_config, save_config)
    from bmc_results import get_results
except ImportError:
    respond('503 Service Unavailable', {'success': False, 'error':
            'BMC support is not installed; complete the LLDPq update'})

action = sys.argv[1]
method = os.environ.get('REQUEST_METHOD', 'GET').upper()
expected_method = {'config': 'GET', 'results': 'GET', 'save': 'POST'}.get(action)
if expected_method is None:
    respond('400 Bad Request', {'success': False, 'error': 'Unknown BMC action'})
if method != expected_method:
    respond('405 Method Not Allowed', {'success': False, 'error':
            expected_method + ' method required'})

devices = root / 'devices.yaml'
config = root / 'bmc.yaml'


@contextmanager
def inventory_lock():
    """Serialize saved mappings with Setup/Provision inventory changes.

    All writers take inventory before the BMC file lock; read-only results
    remain available while a configuration writer is working.
    """
    path = Path(os.environ['WEB_ROOT']) / '.inventory.lock'
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_CLOEXEC', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags, 0o660)
    with os.fdopen(descriptor, 'r+') as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & stat.S_IWOTH:
            raise BMCConfigError('Inventory lock has unsafe type or permissions')
        if metadata.st_uid == os.geteuid():
            # A restrictive CGI umask must not lock the service user out.
            os.fchmod(handle.fileno(), stat.S_IMODE(metadata.st_mode) | 0o660)
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


try:
    if action == 'config':
        result = get_config(devices, config)
    elif action == 'results':
        result = get_results(devices, config, root / 'monitor-results/fabric-tables')
    else:
        content_type = os.environ.get('CONTENT_TYPE', '').split(';', 1)[0].strip().lower()
        if content_type != 'application/json':
            respond('415 Unsupported Media Type', {'success': False,
                    'error': 'Content-Type application/json required'})
        length_text = os.environ.get('CONTENT_LENGTH', '')
        if not length_text.isascii() or not length_text.isdecimal():
            respond('400 Bad Request', {'success': False, 'error': 'Invalid Content-Length'})
        length = int(length_text)
        if length > 2 * 1024 * 1024:
            respond('413 Content Too Large', {'success': False, 'error': 'BMC configuration exceeds 2 MiB'})
        raw = sys.stdin.buffer.read(length)
        if len(raw) != length:
            respond('400 Bad Request', {'success': False, 'error': 'Incomplete request body'})
        try:
            def reject_constant(value):
                raise ValueError('Invalid JSON constant: ' + value)
            body = json.loads(raw, parse_constant=reject_constant)
        except (ValueError, UnicodeError):
            respond('400 Bad Request', {'success': False, 'error': 'Invalid JSON body'})
        if not isinstance(body, dict):
            respond('400 Bad Request', {'success': False, 'error': 'JSON object required'})
        with inventory_lock():
            result = save_config(devices, config, body.get('mappings'), body.get('revision'),
                                 file_group=os.environ.get('LLDPQ_BMC_FILE_GROUP', 'www-data'))
except BMCConflictError as exc:
    respond('409 Conflict', {'success': False, 'conflict': True,
            'error': str(exc), 'revision': exc.revision})
except BMCValidationError as exc:
    respond('400 Bad Request', {'success': False, 'error': str(exc)})
except (BMCConfigError, OSError) as exc:
    respond('503 Service Unavailable', {'success': False, 'error': str(exc)})
except Exception:
    respond('500 Internal Server Error', {'success': False,
            'error': 'BMC request could not be completed'})
respond('200 OK', result)
PYTHON
