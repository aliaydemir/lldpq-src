#!/bin/bash
# inventory-api.sh - Inventory / Bootstrap design API
# Backend for the Inventory page (P2P + IPAM design upload, versioning, and
# deterministic artifact generation).
#
# Mirrors the fabric-api.sh / ai-api.sh conventions:
#   - auth-guard.sh admin gate (same session check as run-device-command)
#   - Content-Type: application/json on every path, including errors
#   - all logic in a stdlib-only python3 heredoc
#
# Versioned design state lives under AI_STATE_DIR/inventory/{p2p,ipam}/ using the
# same 2770 setgid + atomic-write conventions as the rest of the AI state. The
# ACTIVE design is additionally PUBLISHED into the web-served monitor-results
# directory (active-p2p.json / active-ipam.json) so the browser and Ask-AI
# [P2P:]/[IPAM:] tools can fetch it for client-side joins.
#
# Every artifact APPLY reuses setup_safety.py (run as the lldpq user, exactly
# like edit-topology.sh / edit-devices.sh) so it inherits that helper's
# validation, atomic write, and .bak backup, and requires an explicit confirm
# token tying the write to the previewed content. Nothing is ever silently
# overwritten.

# Load allowlisted config through the fixed, root-owned parser (same as ai-api.sh).
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi

LLDPQ_DIR="${LLDPQ_DIR:-/home/lldpq/lldpq}"
LLDPQ_USER="${LLDPQ_USER:-lldpq}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"
AI_STATE_DIR="${AI_STATE_DIR:-/var/lib/lldpq/ai}"
INVENTORY_KEEP="${INVENTORY_KEEP:-10}"

PROVISION_STATE_DIR="${LLDPQ_PROVISION_STATE_DIR:-/var/lib/lldpq/provision-state}"
DIRECT_WRITE_STATE_DIR="${LLDPQ_DIRECT_WRITE_STATE_DIR:-$PROVISION_STATE_DIR/config-write-journals}"

# Helper + target paths (same locations edit-topology.sh / edit-devices.sh use).
SETUP_SAFETY="$(dirname "$0")/setup_safety.py"
AI_GENERATE="$(dirname "$0")/ai_generate.py"
PARSE_DEVICES="$LLDPQ_DIR/parse_devices.py"
TOPOLOGY_EDGES="$LLDPQ_DIR/topology_edges.py"
TOPOLOGY_FILE="$WEB_ROOT/topology.dot"
TOPOLOGY_CONFIG_FILE="$WEB_ROOT/topology_config.yaml"
DEVICES_FILE="$LLDPQ_DIR/devices.yaml"
INVENTORY_LOCK="$WEB_ROOT/.inventory.lock"

# Auth: admin only, identical session guard to the rest of the appliance.
source "$(dirname "$0")/auth-guard.sh"
require_admin

echo "Content-Type: application/json"
echo "Cache-Control: no-store"
echo "X-Content-Type-Options: nosniff"
echo ""

ACTION=$(echo "$QUERY_STRING" | grep -oP 'action=\K[^&]*' | head -1)
KIND=$(echo "$QUERY_STRING"   | grep -oP 'kind=\K[^&]*'   | head -1)
QS_VERSION=$(echo "$QUERY_STRING" | grep -oP 'version=\K[^&]*' | head -1)
QS_MODE=$(echo "$QUERY_STRING"    | grep -oP 'mode=\K[^&]*'    | head -1)
QS_SCOPE=$(echo "$QUERY_STRING"   | grep -oP 'scope=\K[^&]*'   | head -1)
QS_MGMT=$(echo "$QUERY_STRING"    | grep -oP 'mgmt=\K[^&]*'    | head -1)

# Read the raw request body binary-safe (uploads are xlsx). Large/binary bodies
# overflow the kernel per-string env limit on exec, so always spool to a file.
POST_DATA_FILE=""
if [ "$REQUEST_METHOD" = "POST" ] && [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
    POST_DATA_FILE=$(mktemp /tmp/lldpq-inventory.XXXXXX) || POST_DATA_FILE=""
    if [ -n "$POST_DATA_FILE" ]; then
        trap 'rm -f "$POST_DATA_FILE"' EXIT
        dd bs=4096 count=$(( (CONTENT_LENGTH + 4095) / 4096 )) \
            iflag=fullblock 2>/dev/null | head -c "$CONTENT_LENGTH" > "$POST_DATA_FILE"
    fi
fi

export LLDPQ_DIR LLDPQ_USER WEB_ROOT AI_STATE_DIR INVENTORY_KEEP
export DIRECT_WRITE_STATE_DIR SETUP_SAFETY AI_GENERATE PARSE_DEVICES TOPOLOGY_EDGES
export TOPOLOGY_FILE TOPOLOGY_CONFIG_FILE DEVICES_FILE INVENTORY_LOCK
export ACTION KIND QS_VERSION QS_MODE QS_SCOPE QS_MGMT POST_DATA_FILE CONTENT_TYPE

python3 << 'PYTHON_END'
import base64
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True

WEB_ROOT = os.environ.get('WEB_ROOT', '/var/www/html')
LLDPQ_DIR = os.environ.get('LLDPQ_DIR', '/home/lldpq/lldpq')
LLDPQ_USER = os.environ.get('LLDPQ_USER', 'lldpq')
AI_STATE_DIR = os.environ.get('AI_STATE_DIR', '/var/lib/lldpq/ai')
DIRECT_WRITE_STATE_DIR = os.environ.get('DIRECT_WRITE_STATE_DIR', '')
SETUP_SAFETY = os.environ.get('SETUP_SAFETY', '')
PARSE_DEVICES = os.environ.get('PARSE_DEVICES', '')
TOPOLOGY_EDGES = os.environ.get('TOPOLOGY_EDGES', '')
TOPOLOGY_FILE = os.environ.get('TOPOLOGY_FILE', '')
TOPOLOGY_CONFIG_FILE = os.environ.get('TOPOLOGY_CONFIG_FILE', '')
DEVICES_FILE = os.environ.get('DEVICES_FILE', '')
INVENTORY_LOCK = os.environ.get('INVENTORY_LOCK', '')
ACTION = os.environ.get('ACTION', '')
KIND = os.environ.get('KIND', '')
QS_VERSION = os.environ.get('QS_VERSION', '')
QS_MODE = os.environ.get('QS_MODE', '')
QS_SCOPE = os.environ.get('QS_SCOPE', '')
QS_MGMT = os.environ.get('QS_MGMT', '')
POST_DATA_FILE = os.environ.get('POST_DATA_FILE', '')

try:
    INVENTORY_KEEP = max(1, int(os.environ.get('INVENTORY_KEEP', '10')))
except ValueError:
    INVENTORY_KEEP = 10

INVENTORY_DIR = os.path.join(AI_STATE_DIR, 'inventory')
MR_DIR = os.path.join(WEB_ROOT, 'monitor-results')

# ai_generate / ai_p2p / ai_ipam live next to this script in the web root.
if WEB_ROOT not in sys.path:
    sys.path.insert(0, WEB_ROOT)
_HERE = os.path.dirname(os.path.abspath(SETUP_SAFETY)) if SETUP_SAFETY else WEB_ROOT
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import ai_generate  # noqa: E402
import ai_p2p       # noqa: E402


def fail(msg, **extra):
    out = {'success': False, 'error': str(msg)}
    out.update(extra)
    print(json.dumps(out, ensure_ascii=False))
    sys.exit(0)


def ok(**data):
    out = {'success': True}
    out.update(data)
    print(json.dumps(out, ensure_ascii=False))
    sys.exit(0)


# --------------------------------------------------------------------------
# State directory + atomic writes (same shape as ai-api.sh _save_json_state)
# --------------------------------------------------------------------------

def ensure_dir(path, mode=0o2770):
    try:
        os.makedirs(path, mode=mode, exist_ok=True)
        return
    except PermissionError:
        pass
    for cmd in (
        ['sudo', '-n', 'mkdir', '-p', path],
        ['sudo', '-n', 'chown', '%s:www-data' % LLDPQ_USER, path],
        ['sudo', '-n', 'chmod', '2770', path],
    ):
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            fail('Cannot create inventory state directory: %s'
                 % (result.stderr.strip() or path))


def atomic_write(path, text, mode=0o660):
    directory = os.path.dirname(path)
    ensure_dir(directory)
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix='.%s.tmp-' % os.path.basename(path), dir=directory)
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        tmp = None
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def load_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# setup_safety.py bridge (validation + atomic write + .bak, run as lldpq user)
# --------------------------------------------------------------------------

def run_setup_safety(args, stdin_text=''):
    if not SETUP_SAFETY or not os.path.exists(SETUP_SAFETY):
        return None, 'Setup safety helper is missing; repair the installation'
    cmd = ['sudo', '-n', '-H', '-u', LLDPQ_USER, '/usr/bin/bash', '-c',
           'exec python3 "$@"', '--', SETUP_SAFETY] + list(args)
    try:
        proc = subprocess.run(cmd, input=stdin_text, capture_output=True,
                              text=True, timeout=60)
    except subprocess.SubprocessError as exc:
        return None, 'Configuration write helper failed: %s' % exc
    out = (proc.stdout or '').strip()
    if not out:
        return None, (proc.stderr or '').strip() or 'Configuration write helper returned nothing'
    try:
        return json.loads(out), None
    except ValueError:
        return None, 'Configuration write helper returned invalid JSON'


def read_devices_text():
    result, _ = run_setup_safety(
        ['read-devices', '--target', DEVICES_FILE, '--managed-root', LLDPQ_DIR,
         '--inventory-lock', INVENTORY_LOCK,
         '--direct-write-state-dir', DIRECT_WRITE_STATE_DIR])
    if isinstance(result, dict) and result.get('success'):
        return result.get('content', ''), result.get('revision')
    try:
        with open(DEVICES_FILE, 'r', encoding='utf-8') as fh:
            return fh.read(), None
    except OSError:
        return '', None


# --------------------------------------------------------------------------
# Versioned design storage
# --------------------------------------------------------------------------

_KIND_DIRS = {'p2p': os.path.join(INVENTORY_DIR, 'p2p'),
              'ipam': os.path.join(INVENTORY_DIR, 'ipam')}
_VERSION_RE = re.compile(r'^\d+-[0-9a-f]{8}\.json$')


def kind_dir(kind):
    path = _KIND_DIRS.get(kind)
    if not path:
        fail("kind must be 'p2p' or 'ipam'")
    return path


def active_pointer_path(kind):
    return os.path.join(kind_dir(kind), 'active.json')


def list_versions(kind):
    directory = kind_dir(kind)
    active = (load_json(active_pointer_path(kind)) or {}).get('active', '')
    out = []
    try:
        names = os.listdir(directory)
    except OSError:
        names = []
    for name in names:
        if not _VERSION_RE.match(name):
            continue
        wrapper = load_json(os.path.join(directory, name)) or {}
        out.append({
            'version': name,
            'filename': wrapper.get('filename', ''),
            'ts': wrapper.get('ts', 0),
            'sha': wrapper.get('sha', ''),
            'summary': wrapper.get('summary', {}),
            'active': (name == active),
        })
    out.sort(key=lambda item: item.get('ts', 0), reverse=True)
    return out


def prune_versions(kind):
    """Keep the newest INVENTORY_KEEP versions; never delete the active one.

    This IS the single silent prior backup: a wrong upload stays recoverable
    because the previous versions are retained (no version-diff UI, per spec)."""
    directory = kind_dir(kind)
    active = (load_json(active_pointer_path(kind)) or {}).get('active', '')
    versions = [v for v in list_versions(kind)]
    for stale in versions[INVENTORY_KEEP:]:
        if stale['version'] == active:
            continue
        try:
            os.unlink(os.path.join(directory, stale['version']))
        except OSError:
            pass


def store_version(kind, filename, data, raw_bytes):
    directory = kind_dir(kind)
    ensure_dir(directory)
    sha = hashlib.sha256(raw_bytes).hexdigest()[:8]
    ts = int(time.time())
    version = '%d-%s.json' % (ts, sha)
    wrapper = {
        'kind': kind,
        'filename': filename,
        'ts': ts,
        'sha': sha,
        'summary': summarize(kind, data),
        'data': data,
    }
    atomic_write(os.path.join(directory, version), json.dumps(wrapper, ensure_ascii=False))
    prune_versions(kind)
    return version, wrapper['summary']


def load_version(kind, version=''):
    directory = kind_dir(kind)
    if not version:
        version = (load_json(active_pointer_path(kind)) or {}).get('active', '')
    if not version:
        return None, ''
    if not _VERSION_RE.match(version):
        fail('invalid version id')
    wrapper = load_json(os.path.join(directory, version))
    if not wrapper:
        return None, version
    return wrapper, version


def summarize(kind, data):
    if kind == 'p2p':
        try:
            resolved = len(ai_p2p.expected_links(data))
        except Exception:
            resolved = 0
        conns = data.get('connections', []) if isinstance(data, dict) else []
        return {
            'total_connections': data.get('total_connections', len(conns)) if isinstance(data, dict) else 0,
            'resolved_links': resolved,
            'unresolved': sum(1 for c in conns if c.get('unresolved')),
        }
    return {
        'total_records': data.get('total_records', 0) if isinstance(data, dict) else 0,
        'subnets': len(data.get('subnets', [])) if isinstance(data, dict) else 0,
        'hosts': len(data.get('hosts', [])) if isinstance(data, dict) else 0,
        'fabric': len(data.get('fabric', [])) if isinstance(data, dict) else 0,
        'l3_links': len(data.get('l3_links', [])) if isinstance(data, dict) else 0,
    }


# --------------------------------------------------------------------------
# Request body parsing (multipart file upload OR JSON with base64 / canonical)
# --------------------------------------------------------------------------

def read_body_bytes():
    if POST_DATA_FILE and os.path.exists(POST_DATA_FILE):
        try:
            with open(POST_DATA_FILE, 'rb') as fh:
                return fh.read()
        except OSError:
            return b''
    return b''


def parse_multipart(body, content_type):
    match = re.search(r'boundary=("?)([^";]+)\1', content_type)
    if not match:
        return {}, {}
    boundary = ('--' + match.group(2)).encode()
    files, fields = {}, {}
    for part in body.split(boundary):
        part = part.strip(b'\r\n')
        if not part or part == b'--':
            continue
        if b'\r\n\r\n' not in part:
            continue
        head, payload = part.split(b'\r\n\r\n', 1)
        head_text = head.decode('utf-8', 'replace')
        name_m = re.search(r'name="([^"]*)"', head_text)
        file_m = re.search(r'filename="([^"]*)"', head_text)
        if not name_m:
            continue
        payload = payload.rstrip(b'\r\n')
        if file_m and file_m.group(1):
            files[name_m.group(1)] = (file_m.group(1), payload)
        else:
            fields[name_m.group(1)] = payload.decode('utf-8', 'replace')
    return files, fields


def parse_json_body(body):
    try:
        return json.loads(body.decode('utf-8', 'replace'))
    except ValueError:
        return None


def infer_kind(filename, given):
    if given in ('p2p', 'ipam'):
        return given
    low = filename.lower()
    if re.search(r'ipam|ip[-_ ]?alloc|addressing|subnet', low):
        return 'ipam'
    if re.search(r'p2p|connection|cabl|point[-_ ]?to[-_ ]?point', low):
        return 'p2p'
    return ''


def parse_design(kind, filename, filebytes):
    suffix = os.path.splitext(filename)[1].lower()
    if suffix in ('.xlsx', '.xlsm', '.xltx', '.xltm'):
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(suffix=suffix, prefix='lldpq-upl-')
            with os.fdopen(fd, 'wb') as fh:
                fh.write(filebytes)
            if kind == 'p2p':
                import ai_p2p as _p
                return _p.parse_workbook(tmp)
            import ai_ipam as _i
            return _i.parse_workbook(tmp)
        finally:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
    if suffix == '.json':
        text = filebytes.decode('utf-8', 'replace')
        if kind == 'p2p':
            import ai_p2p as _p
            return _p.load_connections(text)
        obj = json.loads(text)
        if not (isinstance(obj, dict) and (obj.get('format') == 'ipam'
                or 'fabric' in obj or 'hosts' in obj or 'subnets' in obj)):
            raise ValueError('IPAM JSON must be a parsed ai_ipam design')
        return obj
    raise ValueError('unsupported file type %r (expected .xlsx/.xlsm/.json)' % suffix)


# --------------------------------------------------------------------------
# Publish active design into the web-served monitor-results directory
# --------------------------------------------------------------------------

def publish_active(kind, wrapper):
    published = dict(wrapper.get('data') or {})
    published['_active_version'] = wrapper.get('version') or wrapper.get('sha', '')
    published['_activated_at'] = int(time.time())
    published['_source_file'] = wrapper.get('filename', '')
    text = json.dumps(published, ensure_ascii=False)
    target = os.path.join(MR_DIR, 'active-%s.json' % kind)
    # Prefer a direct atomic write (monitor-results is normally www-data
    # writable); fall back to setup_safety save-text as the lldpq user.
    tmp = None
    try:
        os.makedirs(MR_DIR, exist_ok=True)
        directory = MR_DIR
        fd, tmp = tempfile.mkstemp(prefix='.active-%s.tmp-' % kind, dir=directory)
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, 'w') as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
        tmp = None
        return True, None
    except (OSError, PermissionError):
        # Never leak the temp file into the web-served directory.
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        result, err = run_setup_safety(
            ['save-text', '--request-json', '--target', target,
             '--managed-root', WEB_ROOT,
             '--direct-write-state-dir', DIRECT_WRITE_STATE_DIR],
            json.dumps({'content': text}))
        if isinstance(result, dict) and result.get('success'):
            return True, None
        return False, err or (result or {}).get('error') or 'publish failed'


# --------------------------------------------------------------------------
# Confirm-token gate for artifact apply
# --------------------------------------------------------------------------

def content_token(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------

def action_upload():
    body = read_body_bytes()
    if not body:
        fail('empty upload')
    content_type = os.environ.get('CONTENT_TYPE', '')
    kind = KIND
    filename = ''
    filebytes = b''
    if 'multipart/form-data' in content_type:
        files, fields = parse_multipart(body, content_type)
        kind = fields.get('kind', kind)
        if files:
            _, (filename, filebytes) = next(iter(files.items()))
    else:
        payload = parse_json_body(body)
        if not isinstance(payload, dict):
            fail('unrecognized upload body (expected multipart form or JSON)')
        kind = payload.get('kind', kind)
        filename = payload.get('filename', '')
        if payload.get('content_b64'):
            try:
                filebytes = base64.b64decode(payload['content_b64'])
            except (ValueError, TypeError):
                fail('content_b64 is not valid base64')
        elif isinstance(payload.get('data'), dict):
            # Pre-parsed canonical design passed straight through.
            k = infer_kind(filename, kind)
            if k not in ('p2p', 'ipam'):
                fail("kind must be 'p2p' or 'ipam'")
            version, summary = store_version(k, filename or 'design.json',
                                             payload['data'], body)
            ok(kind=k, version=version, filename=filename or 'design.json', summary=summary)
    if not filebytes:
        fail('no file content in upload')
    kind = infer_kind(filename, kind)
    if kind not in ('p2p', 'ipam'):
        fail("kind must be 'p2p' or 'ipam' (could not infer from filename)")
    if len(filebytes) > 64 * 1024 * 1024:
        fail('upload too large')
    try:
        data = parse_design(kind, filename or ('design.xlsx' if kind else ''), filebytes)
    except Exception as exc:
        fail('parse failed: %s' % exc)
    version, summary = store_version(kind, filename or 'design', data, filebytes)
    ok(kind=kind, version=version, filename=filename, summary=summary,
       warnings=(data.get('warnings', [])[:20] if isinstance(data, dict) else []))


def action_list():
    ensure_dir(INVENTORY_DIR)
    # Self-heal: an activation whose publish step failed (or a wiped
    # monitor-results) leaves the active pointer without its web-served copy.
    # Every Inventory page load repairs that quietly.
    republished = {}
    for kind in ('p2p', 'ipam'):
        target = os.path.join(MR_DIR, 'active-%s.json' % kind)
        if os.path.exists(target):
            continue
        wrapper, version = load_version(kind, '')
        if not wrapper:
            continue
        wrapper['version'] = version
        okp, perr = publish_active(kind, wrapper)
        republished[kind] = True if okp else (perr or 'publish failed')
    ok(versions={'p2p': list_versions('p2p'), 'ipam': list_versions('ipam')},
       keep=INVENTORY_KEEP, republished=republished)


def action_active_design():
    kind = KIND or 'p2p'
    if kind not in ('p2p', 'ipam'):
        fail("kind must be 'p2p' or 'ipam'")
    wrapper, version = load_version(kind, '')
    if not wrapper:
        fail('no active %s design' % kind)
    wrapper['version'] = version
    # Serve the design straight from the version store so consumers never
    # depend on the published static copy; republish it while we are here.
    published, perr = publish_active(kind, wrapper)
    payload = dict(wrapper.get('data') or {})
    payload['_active_version'] = version
    payload['_source_file'] = wrapper.get('filename', '')
    ok(kind=kind, version=version, published=published, publish_error=perr,
       design=payload)


def action_activate():
    body = read_body_bytes()
    payload = parse_json_body(body) if body else {}
    if not isinstance(payload, dict):
        payload = {}
    kind = payload.get('kind') or KIND
    version = payload.get('version') or QS_VERSION
    if kind not in ('p2p', 'ipam'):
        fail("kind must be 'p2p' or 'ipam'")
    wrapper, version = load_version(kind, version)
    if not wrapper:
        fail('version not found')
    wrapper['version'] = version
    pointer = active_pointer_path(kind)
    prior = load_json(pointer)
    if prior is not None:
        # A single silent backup of the prior active pointer (no diff UI).
        try:
            atomic_write(pointer + '.bak', json.dumps(prior, ensure_ascii=False))
        except OSError:
            pass
    atomic_write(pointer, json.dumps({'active': version, 'ts': int(time.time())}))
    published, perr = publish_active(kind, wrapper)
    ok(kind=kind, version=version, published=published,
       publish_error=perr, summary=wrapper.get('summary', {}))


def action_delete():
    body = read_body_bytes()
    payload = parse_json_body(body) if body else {}
    if not isinstance(payload, dict):
        payload = {}
    kind = payload.get('kind') or KIND
    version = payload.get('version') or QS_VERSION
    if kind not in ('p2p', 'ipam'):
        fail("kind must be 'p2p' or 'ipam'")
    if not version or not _VERSION_RE.match(str(version)):
        fail('invalid version id')
    directory = kind_dir(kind)
    active = (load_json(active_pointer_path(kind)) or {}).get('active', '')
    if version == active:
        fail('cannot delete the active version; activate another version first')
    path = os.path.join(directory, version)
    if not os.path.exists(path):
        fail('version not found')
    try:
        os.unlink(path)
    except OSError as exc:
        fail('delete failed: %s' % exc)
    ok(kind=kind, version=version, versions=list_versions(kind))


def action_bootstrap_status():
    # Feature probe for the optional Bootstrap Advisor. No advisor backend
    # ships yet; a future backend flips available to reveal the panel.
    ok(available=False)


def action_validate():
    kind = KIND or 'p2p'
    if kind not in ('p2p', 'ipam'):
        fail("kind must be 'p2p' or 'ipam'")
    wrapper, version = load_version(kind, QS_VERSION)
    if not wrapper:
        fail('no %s design (upload and activate one first)' % kind)
    data = wrapper.get('data') or {}
    if kind == 'p2p':
        report = ai_generate.validate_p2p(data)
    else:
        report = validate_ipam(data)
    ok(kind=kind, version=version, report=report)


def validate_ipam(data):
    issues = []
    seen = {}
    ip_owner = {}
    for record in data.get('fabric', []):
        host = str(record.get('hostname') or record.get('device') or '').strip()
        if not host:
            continue
        key = host.casefold()
        if key in seen:
            issues.append({'severity': 'warning', 'kind': 'duplicate-record',
                           'message': 'duplicate fabric record for %s' % host})
        else:
            seen[key] = True
        mgmt_ip = str(record.get('mgmt_ip') or '').strip()
        if not mgmt_ip:
            issues.append({'severity': 'warning', 'kind': 'missing-mgmt-ip',
                           'message': '%s has no mgmt_ip (record is skipped by the devices.yaml generator)' % host})
            continue
        try:
            ipaddress.ip_address(mgmt_ip)
        except ValueError:
            issues.append({'severity': 'error', 'kind': 'invalid-mgmt-ip',
                           'message': '%s has an invalid mgmt_ip: %s' % (host, mgmt_ip)})
            continue
        owner = ip_owner.get(mgmt_ip)
        if owner and owner.casefold() != key:
            issues.append({'severity': 'error', 'kind': 'duplicate-mgmt-ip',
                           'message': 'mgmt_ip %s is assigned to both %s and %s' % (mgmt_ip, owner, host)})
        else:
            ip_owner[mgmt_ip] = host
    counts = {
        'subnets': len(data.get('subnets', [])),
        'hosts': len(data.get('hosts', [])),
        'fabric': len(data.get('fabric', [])),
        'l3_links': len(data.get('l3_links', [])),
    }
    order = {'error': 0, 'warning': 1, 'info': 2}
    issues.sort(key=lambda i: order.get(i['severity'], 3))
    return {'issues': issues, 'counts': counts, 'warnings': list(data.get('warnings', []))}


def _load_active(kind):
    wrapper, version = load_version(kind, '')
    if not wrapper:
        fail('no active %s design (activate one first)' % kind)
    return wrapper.get('data') or {}, version


def _apply_request():
    body = read_body_bytes()
    payload = parse_json_body(body) if body else {}
    return payload if isinstance(payload, dict) else {}


def _reverse_display_aliases():
    """{lower(designLabel): liveName} maps from display-aliases.json (both
    namespaces), so generated files carry the names LLDP actually reports.
    Missing/empty alias file means no translation."""
    try:
        with open(os.path.join(WEB_ROOT, 'display-aliases.json'), 'r') as fh:
            data = json.load(fh) or {}
    except (OSError, ValueError):
        return {}, {}

    def reverse(mapping):
        out = {}
        for real, label in (mapping or {}).items():
            if real and label:
                out[str(label).strip().lower()] = str(real).strip()
        return out

    return reverse(data.get('devices')), reverse(data.get('interfaces'))


def action_generate_topology():
    mode = QS_MODE or 'preview'
    # Default mirrors the UI default: the expected topology LLDPq validates is
    # the Ethernet switch fabric; hosts/IB come in via an explicit scope.
    scope = QS_SCOPE or 'sw-to-sw'
    if scope not in ai_generate.TOPOLOGY_SCOPES:
        fail("scope must be one of: %s" % ", ".join(ai_generate.TOPOLOGY_SCOPES))
    include_mgmt = QS_MGMT in ('1', 'true', 'yes', 'on')
    data, version = _load_active('p2p')
    device_aliases, port_aliases = _reverse_display_aliases()
    # The IPAM fabric sheet is the authoritative switch list for the sw-to-sw
    # scope (storage appliances may name their NICs swp-style and would fool
    # the port-form fallback heuristic). Optional: absent IPAM design degrades
    # to the heuristic.
    switch_names = set()
    if scope == 'sw-to-sw':
        try:
            ipam_wrapper, _ipam_ver = load_version('ipam', '')
            if ipam_wrapper:
                switch_names = ai_generate.switch_names_from_ipam(
                    ipam_wrapper.get('data') or {})
        except SystemExit:
            raise
        except Exception:
            switch_names = set()
    content = ai_generate.p2p_to_topology_dot(
        data, device_aliases=device_aliases, port_aliases=port_aliases,
        scope=scope, include_mgmt=include_mgmt,
        switch_names=switch_names or None)
    token = content_token(content)
    stats = {'edges': content.count(' -- '), 'source_version': version,
             'scope': scope, 'include_mgmt': include_mgmt,
             'switch_source': ('ipam (%d switches)' % (len(switch_names) // 2)
                               if switch_names else 'heuristic')}
    if mode == 'preview':
        ok(preview=content, token=token, target='topology.dot', stats=stats,
           source_version=version)
    if mode != 'apply':
        fail('mode must be preview or apply')
    payload = _apply_request()
    if payload.get('confirm') != token:
        fail('confirm token missing or stale; re-preview before applying',
             token=token)
    args = ['save-topology', '--request-json', '--target', TOPOLOGY_FILE,
            '--managed-root', WEB_ROOT, '--managed-root', LLDPQ_DIR,
            '--direct-write-state-dir', DIRECT_WRITE_STATE_DIR]
    if os.path.exists(TOPOLOGY_EDGES):
        args += ['--topology-parser', TOPOLOGY_EDGES]
    result, err = run_setup_safety(args, json.dumps({'content': content}))
    if not (isinstance(result, dict) and result.get('success')):
        fail((result or {}).get('error') if isinstance(result, dict) else err
             or 'failed to save topology.dot')
    ok(target='topology.dot', revision=result.get('revision'),
       message='topology.dot saved (previous version backed up to .bak)')


def action_generate_devices():
    mode = QS_MODE or 'preview'
    data, version = _load_active('ipam')
    existing, _rev = read_devices_text()
    result = ai_generate.ipam_to_devices_yaml(data, existing_yaml=existing)
    content = result['yaml']
    token = content_token(content)
    if mode == 'preview':
        ok(preview=content, token=token, target='devices.yaml',
           diff=result['diff'], skipped=result['skipped'], source_version=version)
    if mode != 'apply':
        fail('mode must be preview or apply')
    payload = _apply_request()
    if payload.get('confirm') != token:
        fail('confirm token missing or stale; re-preview before applying',
             token=token)
    args = ['save-devices', '--request-json', '--target', DEVICES_FILE,
            '--parser', PARSE_DEVICES, '--managed-root', LLDPQ_DIR,
            '--inventory-lock', INVENTORY_LOCK,
            '--direct-write-state-dir', DIRECT_WRITE_STATE_DIR]
    r, err = run_setup_safety(args, json.dumps({'content': content}))
    if not (isinstance(r, dict) and r.get('success')):
        fail((r or {}).get('error') if isinstance(r, dict) else err
             or 'failed to save devices.yaml')
    ok(target='devices.yaml', revision=r.get('revision'),
       message='devices.yaml saved (previous version backed up to .bak)')


def action_generate_topology_config():
    mode = QS_MODE or 'preview'
    data, version = _load_active('ipam')
    p2p_wrapper, _ = load_version('p2p', '')
    p2p_data = p2p_wrapper.get('data') if p2p_wrapper else None
    content = ai_generate.ipam_to_topology_config_yaml(data, p2p=p2p_data)
    token = content_token(content)
    if mode == 'preview':
        ok(preview=content, token=token, target='topology_config.yaml',
           source_version=version)
    if mode != 'apply':
        fail('mode must be preview or apply')
    payload = _apply_request()
    if payload.get('confirm') != token:
        fail('confirm token missing or stale; re-preview before applying',
             token=token)
    args = ['save-topology-config', '--request-json', '--target', TOPOLOGY_CONFIG_FILE,
            '--managed-root', WEB_ROOT, '--managed-root', LLDPQ_DIR,
            '--direct-write-state-dir', DIRECT_WRITE_STATE_DIR]
    r, err = run_setup_safety(args, json.dumps({'content': content}))
    if not (isinstance(r, dict) and r.get('success')):
        fail((r or {}).get('error') if isinstance(r, dict) else err
             or 'failed to save topology_config.yaml')
    ok(target='topology_config.yaml', revision=r.get('revision'),
       message='topology_config.yaml saved (previous version backed up to .bak)')


_ACTIONS = {
    'upload': action_upload,
    'list': action_list,
    'activate': action_activate,
    'active-design': action_active_design,
    'delete': action_delete,
    'bootstrap-status': action_bootstrap_status,
    'validate': action_validate,
    'generate-topology': action_generate_topology,
    'generate-devices': action_generate_devices,
    'generate-topology-config': action_generate_topology_config,
}


def main():
    handler = _ACTIONS.get(ACTION)
    if not handler:
        fail('unknown action: %s' % ACTION)
    handler()


try:
    main()
except SystemExit:
    raise
except Exception as exc:
    fail('internal error: %s' % exc)
PYTHON_END
