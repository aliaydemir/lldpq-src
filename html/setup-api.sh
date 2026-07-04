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

# ─── Fast path: raw tarball upload (Setup → Update → Offline). The request body IS the file
# (application/octet-stream), so stream stdin straight to disk in big chunks. The generic
# byte-wise JSON reader below would be far too slow and would corrupt binary data. The
# destination is fixed server-side (no path injection); the action comes via the query string.
case "$QUERY_STRING" in
  *action=upload-src*)
    echo "Content-Type: application/json"
    echo ""
    if [ "$REQUEST_METHOD" != "POST" ]; then echo '{"success": false, "error": "POST required"}'; exit 0; fi
    UP_DEST="/tmp/lldpq-upload-src.tar.gz"
    rm -f "$UP_DEST" 2>/dev/null
    if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
        head -c "$CONTENT_LENGTH" > "$UP_DEST" 2>/dev/null
    else
        cat > "$UP_DEST" 2>/dev/null
    fi
    chmod 644 "$UP_DEST" 2>/dev/null
    UP_SZ=$(wc -c < "$UP_DEST" 2>/dev/null | tr -d ' ')
    UP_MAGIC=$(od -An -tx1 -N2 "$UP_DEST" 2>/dev/null | tr -d ' \n')
    if [ "${UP_SZ:-0}" -gt 0 ] 2>/dev/null && [ "$UP_MAGIC" = "1f8b" ]; then
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
echo ""

# Read POST data
if [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
    POST_DATA=$(dd bs=1 count="$CONTENT_LENGTH" 2>/dev/null)
else
    POST_DATA=$(cat)
fi

# Only accept POST
if [ "$REQUEST_METHOD" != "POST" ]; then
    echo '{"success": false, "error": "POST method required"}'
    exit 0
fi

# Export for Python
export LLDPQ_DIR LLDPQ_USER WEB_ROOT POST_DATA

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
from concurrent.futures import ThreadPoolExecutor, as_completed

CRON_VALIDATOR = '/usr/local/bin/lldpq-config'
BACKUP_IMPORT_HELPER = '/usr/local/libexec/lldpq-backup-import.py'
_CONFIG_LOCK_HANDLE = None

def parse_completion_log(content):
    """Return cleaned log and the real exit status recorded by a detached runner."""
    matches = list(re.finditer(r'(?m)^__LLDPQ_DONE__(?::(-?[0-9]+))?\s*$', content))
    if not matches:
        return content.rstrip(), False, None, False
    raw_code = matches[-1].group(1)
    exit_code = int(raw_code) if raw_code is not None else None
    display = re.sub(r'(?m)^__LLDPQ_DONE__(?::(?:-?[0-9]+)?)?\s*\n?', '', content).rstrip()
    return display, True, exit_code, exit_code == 0

def load_backup_import_helper(module_name):
    """Load only the installer-owned helper, never a service-tree module."""
    try:
        metadata = os.lstat(BACKUP_IMPORT_HELPER)
    except OSError as exc:
        raise RuntimeError(
            'Backup helper is missing; run install.sh to repair this installation.'
        ) from exc
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o755):
        raise RuntimeError(
            'Backup helper ownership/mode is unsafe; run install.sh to repair this installation.'
        )
    spec = importlib.util.spec_from_file_location(module_name, BACKUP_IMPORT_HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError('Backup helper could not be loaded.')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def ensure_configuration_lock():
    """Serialize all /etc/lldpq.conf + cron transactions in this CGI."""
    global _CONFIG_LOCK_HANDLE
    if _CONFIG_LOCK_HANDLE is not None:
        return
    handle = open('/etc/lldpq.conf.lock', 'a+')
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    _CONFIG_LOCK_HANDLE = handle

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

def ensure_ssh_key(lldpq_user):
    """Check if SSH key exists for LLDPQ_USER, generate if missing. Returns (key_path, generated, error)"""
    # Check for existing keys
    for key_type, key_name in [('ed25519', 'id_ed25519'), ('rsa', 'id_rsa')]:
        pub_path = os.path.expanduser(f'~{lldpq_user}/.ssh/{key_name}.pub')
        if os.path.isfile(pub_path):
            return pub_path, False, None
    
    # No key found - generate ed25519
    ssh_dir = os.path.expanduser(f'~{lldpq_user}/.ssh')
    key_path = os.path.join(ssh_dir, 'id_ed25519')
    pub_path = key_path + '.pub'
    
    try:
        # Ensure .ssh directory exists
        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
        
        # Generate key as LLDPQ_USER
        result = subprocess.run(
            ['sudo', '-u', lldpq_user, 'ssh-keygen', '-t', 'ed25519', '-N', '', '-f', key_path],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return None, False, f'ssh-keygen failed: {result.stderr}'
        
        return pub_path, True, None
    except Exception as e:
        return None, False, str(e)

def detect_ping_cmd(lldpq_user):
    """Returns ping command. On Cumulus switches with --privileged, the entrypoint
    adds 'ip rule add pref 100 table <mgmt>' which routes ALL traffic through mgmt VRF.
    So plain 'ping' works without ip vrf exec (which needs BPF/root)."""
    return ['ping']

def ping_check(ip, ping_cmd, timeout=2):
    """Quick ping check - VRF-aware on Cumulus switches."""
    try:
        result = subprocess.run(
            ping_cmd + ['-c', '1', '-W', str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 2
        )
        return result.returncode == 0
    except Exception:
        return False

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
    
    # Step 0: Quick ping check - skip unreachable devices
    if not ping_check(ip, PING_CMD):
        result['send_key'] = 'fail'
        result['send_key_msg'] = 'Unreachable (ping failed)'
        result['sudo_fix'] = 'skipped'
        result['sudo_fix_msg'] = 'Skipped (device unreachable)'
        return result
    
    # Step 1: Check if key already works
    try:
        check = subprocess.run(
            ['sudo', '-u', lldpq_user, 'ssh',
             '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no',
             '-q', f'{username}@{ip}', 'exit'],
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
            # Get the private key path (remove .pub)
            priv_key = ssh_key_path.replace('.pub', '')
            send = subprocess.run(
                ['sudo', '-u', lldpq_user, 'sshpass', '-p', password,
                 'ssh-copy-id', '-o', 'StrictHostKeyChecking=no', '-i', priv_key,
                 f'{username}@{ip}'],
                capture_output=True, text=True, timeout=30
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
            sudo_cmd = (
                f"echo '{password}' | sudo -S bash -c "
                f"'echo \"{username} ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/10_{username} "
                f"&& chmod 440 /etc/sudoers.d/10_{username}'"
            )
            sudo = subprocess.run(
                ['sudo', '-u', lldpq_user, 'sshpass', '-p', password,
                 'ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10',
                 f'{username}@{ip}', sudo_cmd],
                capture_output=True, text=True, timeout=30
            )
            if sudo.returncode == 0:
                result['sudo_fix'] = 'ok'
                result['sudo_fix_msg'] = 'Sudo configured'
            else:
                result['sudo_fix'] = 'fail'
                result['sudo_fix_msg'] = sudo.stderr.strip()[:200] if sudo.stderr else 'sudo setup failed'
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

# Main
try:
    post_data = json.loads(os.environ.get('POST_DATA', '{}'))
except:
    print(json.dumps({'success': False, 'error': 'Invalid JSON'}))
    sys.exit(0)

lldpq_user = os.environ.get('LLDPQ_USER', 'lldpq')
lldpq_dir = os.environ.get('LLDPQ_DIR', '/home/lldpq/lldpq')
web_root = os.environ.get('WEB_ROOT', '/var/www/html')
devices_yaml = os.path.join(lldpq_dir, 'devices.yaml')

# /etc/lldpq.conf keys that are portable (safe to carry in a backup): tunable knobs only.
# NEVER include host paths/identity (LLDPQ_DIR/USER/SRC, WEB_ROOT, *_DIR, DHCP_*, DISCOVERY_RANGE)
# or secrets (AI_API_KEY).
LLDPQ_PREF_KEYS = (
    'LLDPQ_CRON', 'GETCONF_CRON', 'SCAN_INTERVAL', 'SKIP_OPTICAL', 'SKIP_L1',
    'MONITOR_MAX_PARALLEL', 'LLDP_MAX_PARALLEL', 'ASSETS_MAX_PARALLEL',
    'GET_CONFIGS_MAX_PARALLEL', 'GET_CONFIGS_SSH_TIMEOUT',
    'SEND_CMD_MAX_PARALLEL', 'TELEMETRY_MAX_PARALLEL',
    'AUTO_BASE_CONFIG', 'AUTO_ZTP_DISABLE', 'AUTO_SET_HOSTNAME',
    'TRANSCEIVER_FW_SKIP_MODELS', 'TRANSCEIVER_FW_UNKNOWN_MODEL_POLICY',
    'TRANSCEIVER_FW_MAX_PARALLEL', 'TRANSCEIVER_FW_MIN_INTERVAL', 'TRANSCEIVER_FW_SSH_TIMEOUT',
    'TELEMETRY_ENABLED', 'PROMETHEUS_URL', 'AI_PROVIDER', 'AI_MODEL', 'AI_API_URL', 'OLLAMA_URL',
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
    """Use unique fsynced staging and the existing narrow root cp permission."""
    ensure_configuration_lock()
    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(prefix=temp_name + '.', dir='/tmp')
        with os.fdopen(fd, 'w', encoding='utf-8') as staged:
            staged.write(content)
            staged.flush()
            os.fsync(staged.fileno())
        copied = subprocess.run(
            ['sudo', 'cp', temp_path, target], capture_output=True, text=True, timeout=10,
        )
        if copied.returncode != 0:
            return False
        try:
            with open(target, encoding='utf-8') as installed:
                if installed.read() != content:
                    return False
        except Exception:
            return False
        if subprocess.run(
            ['sudo', 'chmod', mode, target], capture_output=True, text=True, timeout=5,
        ).returncode != 0:
            return False
        if subprocess.run(
            ['sudo', 'chown', owner, target],
            capture_output=True, text=True, timeout=5,
        ).returncode != 0:
            return False
        return True
    except Exception:
        return False
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass

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
        '664', 'root:www-data'
    ):
        return True
    # A copy can succeed before a later chmod/chown failure. Restore the exact
    # original bytes before reporting failure so callers get a transaction.
    install_text_as_root(
        original, '/etc/lldpq.conf', '.lldpq.conf.setup.rollback.tmp',
        '664', 'root:www-data'
    )
    return False

# ─── Action: Save existing private key ───
if action == 'save-key':
    private_key = post_data.get('private_key', '').strip()
    if not private_key or 'PRIVATE KEY' not in private_key:
        print(json.dumps({'success': False, 'error': 'Invalid private key'}))
        sys.exit(0)
    
    # Determine key type
    ssh_dir = os.path.expanduser(f'~{lldpq_user}/.ssh')
    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
    
    if 'RSA' in private_key:
        key_file = os.path.join(ssh_dir, 'id_rsa')
    else:
        key_file = os.path.join(ssh_dir, 'id_ed25519')
    
    try:
        # Write private key
        with open(key_file, 'w') as f:
            f.write(private_key + '\n')
        os.chmod(key_file, 0o600)
        
        # Generate public key from private key
        gen = subprocess.run(
            ['ssh-keygen', '-y', '-f', key_file],
            capture_output=True, text=True, timeout=5
        )
        if gen.returncode == 0:
            with open(key_file + '.pub', 'w') as f:
                f.write(gen.stdout.strip() + '\n')
        
        # Fix ownership
        subprocess.run(['chown', '-R', f'{lldpq_user}:{lldpq_user}', ssh_dir],
                      capture_output=True, timeout=5)
        
        # Quick connectivity test: try SSH to first 5 reachable devices
        all_devices, _ = load_devices(devices_yaml)
        reachable = 0
        total = len(all_devices) if all_devices else 0
        
        if all_devices:
            test_devices = all_devices[:10]  # Test first 10
            with ThreadPoolExecutor(max_workers=10) as executor:
                def test_ssh(dev):
                    try:
                        r = subprocess.run(
                            ['sudo', '-u', lldpq_user, 'ssh',
                             '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=3',
                             '-o', 'StrictHostKeyChecking=no', '-q',
                             f"{dev['username']}@{dev['ip']}", 'exit'],
                            capture_output=True, text=True, timeout=8
                        )
                        return r.returncode == 0
                    except:
                        return False
                
                futures = {executor.submit(test_ssh, d): d for d in test_devices}
                for future in as_completed(futures):
                    if future.result():
                        reachable += 1
            
            # Extrapolate: if X/10 work, assume same ratio for all
            if len(test_devices) < total:
                reachable = int((reachable / len(test_devices)) * total)
        
        print(json.dumps({
            'success': True,
            'message': 'Key saved successfully',
            'key_file': key_file,
            'reachable': reachable,
            'total': total
        }))
    except Exception as e:
        print(json.dumps({'success': False, 'error': str(e)}))
    
    sys.exit(0)

# ─── Action: Export the collector PRIVATE key (back up / migrate LLDPq to another host) ───
if action == 'get-private-key':
    private_key = ''
    key_file = ''
    for key_name in ('id_ed25519', 'id_rsa'):
        p = os.path.expanduser(f'~{lldpq_user}/.ssh/{key_name}')
        try:
            r = subprocess.run(['sudo', '-u', lldpq_user, 'cat', p],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and 'PRIVATE KEY' in r.stdout:
                private_key = r.stdout
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
    all_devices, load_error = load_devices(devices_yaml)
    if load_error:
        print(json.dumps({'success': False, 'error': load_error}))
        sys.exit(0)

    PING_CMD = detect_ping_cmd(lldpq_user)

    def verify_device(device):
        ip = device['ip']
        username = device['username']
        res = {'hostname': device['hostname'], 'ip': ip, 'username': username, 'trusted': False, 'msg': ''}
        if not ping_check(ip, PING_CMD):
            res['msg'] = 'Unreachable (ping failed)'
            return res
        try:
            chk = subprocess.run(
                ['sudo', '-u', lldpq_user, 'ssh',
                 '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no',
                 '-q', f'{username}@{ip}', 'exit'],
                capture_output=True, text=True, timeout=10
            )
            if chk.returncode == 0:
                res['trusted'] = True
                res['msg'] = 'Key trusted'
            else:
                res['msg'] = 'Key not accepted (needs distribution)'
        except subprocess.TimeoutExpired:
            res['msg'] = 'Timeout (10s)'
        except Exception as e:
            res['msg'] = str(e)[:120]
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
                                'trusted': False, 'msg': str(e)[:120]})
    results.sort(key=lambda r: r['hostname'])

    # Include the current public key so the page can show it without a separate call.
    public_key = ''
    for key_name in ('id_ed25519', 'id_rsa'):
        pub_path = os.path.expanduser(f'~{lldpq_user}/.ssh/{key_name}.pub')
        if os.path.isfile(pub_path):
            try:
                with open(pub_path) as fh:
                    public_key = fh.read().strip()
            except Exception:
                pass
            break

    trusted = sum(1 for r in results if r['trusted'])
    print(json.dumps({'success': True, 'total': len(results), 'trusted': trusted,
                      'public_key': public_key, 'results': results}))
    sys.exit(0)

# ─── Action: Run the full LLDPq pipeline verbosely (lldpq -) into a log we can tail ───
if action == 'run':
    log_path = os.path.join(lldpq_dir, '.run.log')
    pid_path = os.path.join(lldpq_dir, '.run.pid')
    runner = (
        f'cd {shlex.quote(lldpq_dir)} || {{ echo "ERROR: LLDPq directory is unavailable" >> {shlex.quote(log_path)}; '
        f'printf "__LLDPQ_DONE__:10\\n" >> {shlex.quote(log_path)}; exit 10; }}; '
        f'/usr/local/bin/lldpq - >> {shlex.quote(log_path)} 2>&1; '
        f'rc=$?; printf "__LLDPQ_DONE__:%s\\n" "$rc" >> {shlex.quote(log_path)}; '
        f'rm -f {shlex.quote(pid_path)}; exit "$rc"'
    )
    try:
        prep = subprocess.run(
            ['sudo', '-u', lldpq_user, 'bash', '-c', ': > ' + shlex.quote(log_path)],
            capture_output=True, text=True, timeout=10,
        )
        if prep.returncode != 0:
            print(json.dumps({'success': False, 'error': 'Could not create the LLDPq run log: ' + (prep.stderr or '').strip()[:200]}))
            sys.exit(0)
        launch = (
            f'rm -f {shlex.quote(pid_path)}; '
            f'nohup setsid bash -c {shlex.quote(runner)} >/dev/null 2>&1 & '
            f'printf "%s\\n" "$!" > {shlex.quote(pid_path)}'
        )
        subprocess.Popen(['sudo', '-u', lldpq_user, 'bash', '-c', launch],
                         start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(json.dumps({'success': True, 'message': 'LLDPq run started'}))
    except Exception as e:
        print(json.dumps({'success': False, 'error': str(e)}))
    sys.exit(0)

# ─── Action: Tail the run log started by action=run ───
if action == 'run-log':
    log_path = os.path.join(lldpq_dir, '.run.log')
    pid_path = os.path.join(lldpq_dir, '.run.pid')
    content = ''
    try:
        r = subprocess.run(['sudo', '-u', lldpq_user, 'cat', log_path],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            content = r.stdout
    except Exception:
        content = ''
    display, done, exit_code, ok = parse_completion_log(content)
    running = False
    pid_recorded = False
    if not done:
        try:
            with open(pid_path, 'r', encoding='utf-8') as source:
                pid_text = source.read().strip()
            if re.fullmatch(r'[1-9][0-9]*', pid_text):
                pid_recorded = True
                try:
                    os.kill(int(pid_text), 0)
                    running = True
                except PermissionError:
                    # The CGI user normally differs from LLDPQ_USER; EPERM still
                    # proves that the recorded process exists.
                    running = True
                except ProcessLookupError:
                    running = False
        except (OSError, subprocess.SubprocessError):
            running = False
    print(json.dumps({'success': True, 'done': done, 'ok': ok,
                      'running': running, 'pid_recorded': pid_recorded,
                      'exit_code': exit_code,
                      'log': display}))
    sys.exit(0)

# ─── Action: Ansible integration status (current dir, enabled?, auto-detected candidates) ───
if action == 'get-ansible':
    conf = read_conf()
    raw = conf.get('ANSIBLE_DIR', '')
    disabled = (raw == '' or raw == 'NoNe')
    path = '' if disabled else raw
    exists = bool(path) and os.path.isdir(path) and os.path.isdir(os.path.join(path, 'inventory'))
    home = os.path.expanduser('~' + lldpq_user)
    candidates = []
    try:
        for name in sorted(os.listdir(home)):
            d = os.path.join(home, name)
            if os.path.isdir(os.path.join(d, 'inventory')) and os.path.isdir(os.path.join(d, 'playbooks')):
                candidates.append(d)
    except Exception:
        pass
    print(json.dumps({'success': True, 'disabled': disabled, 'path': path,
                      'exists': exists, 'candidates': candidates}))
    sys.exit(0)

# ─── Action: enable/point/disable Ansible integration (writes ANSIBLE_DIR, NoNe = off) ───
if action == 'set-ansible':
    disable = bool(post_data.get('disable'))
    val = (post_data.get('ansible_dir') or '').strip()
    if disable or not val:
        new_val = 'NoNe'
    else:
        if not (os.path.isdir(val) and os.path.isdir(os.path.join(val, 'inventory'))):
            print(json.dumps({'success': False, 'error': 'Directory not found or missing an inventory/ folder: ' + val}))
            sys.exit(0)
        new_val = val
    if write_conf({'ANSIBLE_DIR': new_val}):
        print(json.dumps({'success': True, 'disabled': new_val == 'NoNe',
                          'path': '' if new_val == 'NoNe' else new_val}))
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
    backup = bool(post_data.get('backup'))
    url = 'https://github.com/aliaydemir/lldpq-src.git'
    # Stage the runner + log in ~/.lldpq-state, NOT inside lldpq_dir: install.sh wipes/
    # replaces the lldpq dir during an update (that's why it preserves data), which would
    # delete the log mid-run. A dedicated hidden dir in HOME survives the install and keeps
    # the home directory tidy.
    home_dir = os.path.expanduser('~' + lldpq_user)
    state_dir = os.path.join(home_dir, '.lldpq-state')
    subprocess.run(['sudo', '-u', lldpq_user, 'mkdir', '-p', state_dir],
                   capture_output=True, text=True, timeout=10)
    script_path = os.path.join(state_dir, 'update-run.sh')
    log_path = os.path.join(state_dir, 'update.log')
    SCRIPT = '''#!/usr/bin/env bash
if [[ -x /usr/local/bin/lldpq-config ]]; then
    eval "$(/usr/local/bin/lldpq-config 2>/dev/null)" || true
fi
SRC="${LLDPQ_SRC:-}"
HOMESRC="$HOME/lldpq-src"
URL="__URL__"
LOG="__LOG__"
: > "$LOG"
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
              .replace('__LOG__', log_path))
    try:
        w = subprocess.run(['sudo', '-u', lldpq_user, 'tee', script_path],
                           input=script, capture_output=True, text=True, timeout=10)
        if w.returncode != 0:
            print(json.dumps({'success': False, 'error': 'Could not stage update script'}))
            sys.exit(0)
        clear = subprocess.run(
            ['sudo', '-u', lldpq_user, 'bash', '-c', ': > ' + shlex.quote(log_path)],
            capture_output=True, text=True, timeout=10,
        )
        if clear.returncode != 0:
            print(json.dumps({'success': False, 'error': 'Could not initialize update log'}))
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
        subprocess.Popen(['sudo', '-u', lldpq_user, 'bash', '-c', launch],
                         start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(json.dumps({'success': True, 'message': 'Update started'}))
    except Exception as e:
        print(json.dumps({'success': False, 'error': str(e)}))
    sys.exit(0)

# ─── Action: Offline Update (apply a source tarball already on the host; no network/GitHub) ───
if action == 'update-offline':
    # Docker: a container can't replace its own image — update is a host operation.
    if os.path.exists('/.dockerenv'):
        print(json.dumps({'success': False, 'docker': True,
                          'error': 'Docker deployment: update on the host (docker load + docker compose up). See the instructions on this page.'}))
        sys.exit(0)
    backup = bool(post_data.get('backup'))
    tarball = (post_data.get('path') or '/tmp/lldpq-src.tar.gz').strip()
    # Strict path: absolute, no traversal, no shell metacharacters (it is substituted into the
    # runner script below, so this also prevents shell injection).
    if not re.match(r'^/[A-Za-z0-9._/-]+$', tarball) or '..' in tarball:
        print(json.dumps({'success': False, 'error': 'Enter a simple absolute path like /tmp/lldpq-src.tar.gz (letters, digits, . _ - / only).'}))
        sys.exit(0)
    home_dir = os.path.expanduser('~' + lldpq_user)
    state_dir = os.path.join(home_dir, '.lldpq-state')
    subprocess.run(['sudo', '-u', lldpq_user, 'mkdir', '-p', state_dir],
                   capture_output=True, text=True, timeout=10)
    script_path = os.path.join(state_dir, 'update-run.sh')
    log_path = os.path.join(state_dir, 'update.log')
    # Same log + systemd-run isolation as action=update, so the existing update-log polling
    # and the UI live view work unchanged. The only difference is the source: extract a local
    # tarball instead of git pull/clone, then run install.sh -y (update mode = offline-safe:
    # it skips apt/pip/Monaco which only run on a fresh install).
    SCRIPT = '''#!/usr/bin/env bash
TARBALL="__TARBALL__"
DEST="$HOME/lldpq-src"
LOG="__LOG__"
: > "$LOG"
(
  TMP=""
  trap '[ -z "$TMP" ] || rm -rf "$TMP"' EXIT
  echo "=== LLDPq Offline Update $(date) ==="
  echo "--- tarball: $TARBALL ---"
  if [ ! -f "$TARBALL" ]; then echo "ERROR: tarball not found (or not readable by $(whoami)): $TARBALL"; exit 1; fi
  TMP="$(mktemp -d)"
  echo "--- extracting ---"
  if ! tar -xzf "$TARBALL" -C "$TMP" 2>&1; then echo "ERROR: extract failed (is this a valid .tar.gz?)"; exit 1; fi
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
  ./install.sh -y __BACKUP__ 2>&1
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
              .replace('__LOG__', log_path))
    try:
        w = subprocess.run(['sudo', '-u', lldpq_user, 'tee', script_path],
                           input=script, capture_output=True, text=True, timeout=10)
        if w.returncode != 0:
            print(json.dumps({'success': False, 'error': 'Could not stage update script'}))
            sys.exit(0)
        clear = subprocess.run(
            ['sudo', '-u', lldpq_user, 'bash', '-c', ': > ' + shlex.quote(log_path)],
            capture_output=True, text=True, timeout=10,
        )
        if clear.returncode != 0:
            print(json.dumps({'success': False, 'error': 'Could not initialize update log'}))
            sys.exit(0)
        launch = ('if sudo systemd-run --no-block --collect '
                  '--uid=' + shlex.quote(lldpq_user) + ' '
                  '--setenv=HOME=' + shlex.quote(home_dir) + ' '
                  '/bin/bash ' + shlex.quote(script_path) + ' 2>/dev/null; then :; '
                  'else nohup setsid /bin/bash ' + shlex.quote(script_path) + ' >/dev/null 2>&1 & fi')
        subprocess.Popen(['sudo', '-u', lldpq_user, 'bash', '-c', launch],
                         start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(json.dumps({'success': True, 'message': 'Offline update started'}))
    except Exception as e:
        print(json.dumps({'success': False, 'error': str(e)}))
    sys.exit(0)

# ─── Action: Tail the update log started by action=update ───
if action == 'update-log':
    log_path = os.path.join(os.path.expanduser('~' + lldpq_user), '.lldpq-state', 'update.log')
    content = ''
    try:
        r = subprocess.run(['sudo', '-u', lldpq_user, 'cat', log_path],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            content = r.stdout
    except Exception:
        content = ''
    display, done, exit_code, ok = parse_completion_log(content)
    print(json.dumps({'success': True, 'done': done, 'ok': ok,
                      'exit_code': exit_code, 'log': display}))
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
    exists = os.path.exists(notif_yaml)
    cfg = {}
    if exists:
        try:
            with open(notif_yaml) as f:
                cfg = yaml.safe_load(f) or {}
        except Exception as e:
            print(json.dumps({'success': False, 'error': 'Cannot parse notifications.yaml: ' + str(e)}))
            sys.exit(0)
    if not isinstance(cfg, dict):
        cfg = {}
    n = cfg.get('notifications') or {}
    slack = n.get('slack') or {}
    thr = cfg.get('thresholds') or {}
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
            'bgp': net.get('bgp_down_minutes'),
            'flap_warn': net.get('link_flaps_per_hour'),
            'flap_crit': net.get('link_flaps_critical'),
            'optical': net.get('optical_power_margin'),
            'cpu': hw.get('cpu_temp_critical'),
            'asic': hw.get('asic_temp_critical'),
            'disk': sysd.get('disk_usage_critical'),
        },
    }
    print(json.dumps({'success': True, 'exists': exists, 'notifications': out}))
    sys.exit(0)

# ─── Action: Write notifications.yaml (preserve unrelated keys; UI-managed) ───
if action == 'set-notifications':
    import yaml
    notif_yaml = os.path.join(lldpq_dir, 'notifications.yaml')
    cfg = {}
    if os.path.exists(notif_yaml):
        try:
            with open(notif_yaml) as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            cfg = {}
    if not isinstance(cfg, dict):
        cfg = {}

    def _sub(parent, key):
        v = parent.get(key)
        if not isinstance(v, dict):
            v = {}
            parent[key] = v
        return v

    def _num(v, default=None):
        try:
            f = float(v)
            return int(f) if f == int(f) else f
        except Exception:
            return default

    n = _sub(cfg, 'notifications')
    slack = _sub(n, 'slack')
    n['enabled'] = bool(post_data.get('enabled'))
    n['server_url'] = str(post_data.get('server_url', '') or '')
    slack['enabled'] = bool(post_data.get('slack_enabled'))
    slack['webhook'] = str(post_data.get('webhook', '') or '')
    slack['channel'] = str(post_data.get('channel', '') or '#lldpq')
    slack.setdefault('username', 'LLDPq Bot')
    slack.setdefault('icon_emoji', ':warning:')

    at = _sub(cfg, 'alert_types')
    at['hardware_alerts'] = bool(post_data.get('t_hardware'))
    at['network_alerts'] = bool(post_data.get('t_network'))
    at['system_alerts'] = bool(post_data.get('t_system'))
    at['topology_alerts'] = bool(post_data.get('t_topology'))
    at['log_alerts'] = bool(post_data.get('t_log'))

    mode = str(post_data.get('mode', 'summary'))
    if mode in ('summary', 'immediate', 'change_only'):
        _sub(cfg, 'alert_strategy')['mode'] = mode
    mi = _num(post_data.get('min_interval'))
    if mi is not None:
        _sub(cfg, 'frequency')['min_interval_minutes'] = mi

    thr = _sub(cfg, 'thresholds')
    net = _sub(thr, 'network')
    hw = _sub(thr, 'hardware')
    sysd = _sub(thr, 'system')
    tin = post_data.get('thresholds') or {}

    def _setnum(d, k, v):
        val = _num(v)
        if val is not None:
            d[k] = val

    _setnum(net, 'bgp_down_minutes', tin.get('bgp'))
    _setnum(net, 'link_flaps_per_hour', tin.get('flap_warn'))
    _setnum(net, 'link_flaps_critical', tin.get('flap_crit'))
    _setnum(net, 'optical_power_margin', tin.get('optical'))
    _setnum(hw, 'cpu_temp_critical', tin.get('cpu'))
    _setnum(hw, 'asic_temp_critical', tin.get('asic'))
    _setnum(sysd, 'disk_usage_critical', tin.get('disk'))

    header = ("# LLDPq Notification Configuration — managed via the Setup page (Notifications).\n"
              "# Slack incoming-webhook guide: https://api.slack.com/messaging/webhooks\n")
    try:
        body = yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False, allow_unicode=True)
    except Exception as e:
        print(json.dumps({'success': False, 'error': 'YAML serialize failed: ' + str(e)}))
        sys.exit(0)
    try:
        w = subprocess.run(['sudo', '-u', lldpq_user, 'tee', notif_yaml],
                           input=header + body, capture_output=True, text=True, timeout=10)
        if w.returncode != 0:
            print(json.dumps({'success': False, 'error': 'Write failed: ' + (w.stderr or '').strip()[:200]}))
            sys.exit(0)
        print(json.dumps({'success': True}))
    except Exception as e:
        print(json.dumps({'success': False, 'error': str(e)}))
    sys.exit(0)

# ─── Action: Send a test Slack message to confirm the webhook works ───
if action == 'test-alert':
    webhook = str(post_data.get('webhook', '') or '').strip()
    channel = str(post_data.get('channel', '') or '').strip()
    if not webhook:
        try:
            import yaml
            with open(os.path.join(lldpq_dir, 'notifications.yaml')) as f:
                c = yaml.safe_load(f) or {}
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

# ─── Action: Export config bundle (devices/topology/topology_config/notifications) ───
if action == 'backup-export':
    import base64, importlib.util, io, tarfile, time as _t
    include_key = bool(post_data.get('include_key'))
    wanted = [('devices.yaml', lldpq_dir), ('topology.dot', lldpq_dir),
              ('topology_config.yaml', lldpq_dir), ('notifications.yaml', lldpq_dir),
              ('display-aliases.json', web_root)]
    buf = io.BytesIO()
    added = []
    has_key = False
    try:
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
                backup_tools.add_regular_tar_member(tar, fn, content, mode=0o600)
                added.append(fn)
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
            acquire_lock=ensure_configuration_lock,
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
    info = _run(['sudo', '-u', lldpq_user, 'bash', '-c',
                 'shopt -s nullglob; f=(~/lldpq-backup-*); echo -n "${#f[@]} "; '
                 'if [ ${#f[@]} -gt 0 ]; then du -scm "${f[@]}" 2>/dev/null | tail -1 | cut -f1; else echo 0; fi'])
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
    r = subprocess.run(['sudo', '-u', lldpq_user, 'bash', '-c',
                        'shopt -s nullglob; f=(~/lldpq-backup-*); n=${#f[@]}; '
                        'm=0; if [ $n -gt 0 ]; then m=$(du -scm "${f[@]}" 2>/dev/null | tail -1 | cut -f1); '
                        'rm -rf "${f[@]}"; fi; echo "$n ${m:-0}"'],
                       capture_output=True, text=True, timeout=120)
    parts = (r.stdout or '').split()
    n = int(parts[0]) if len(parts) >= 1 and parts[0].isdigit() else 0
    mb = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    print(json.dumps({'success': True, 'removed': n, 'freed_mb': mb}))
    sys.exit(0)

# ─── Action: Generate new key + distribute with password ───
password = post_data.get('password', '')
retry_devices = post_data.get('retry_devices', [])  # List of IPs for retry

if not password:
    print(json.dumps({'success': False, 'error': 'Password is required'}))
    sys.exit(0)

# Detect VRF-aware ping command (once, at startup)
PING_CMD = detect_ping_cmd(lldpq_user)

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

print(json.dumps({
    'success': True,
    'key_generated': key_generated,
    'ssh_key': ssh_key_path,
    'total': total,
    'send_key_ok': send_key_ok,
    'sudo_fix_ok': sudo_fix_ok,
    'results': results
}))
PYTHON
