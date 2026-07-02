#!/bin/bash
# setup-api.sh - SSH Setup API (send-key + sudo-fix)
# Backend for SSH Setup modal in assets.html
# Called by nginx fcgiwrap

# Admin-only guard (validates session, exits 401/403 if not admin)
source "$(dirname "$0")/auth-guard.sh"
require_admin

# Load config
if [[ -f /etc/lldpq.conf ]]; then
    source /etc/lldpq.conf
fi

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
from concurrent.futures import ThreadPoolExecutor, as_completed

def load_devices(devices_yaml):
    """Load devices from devices.yaml"""
    try:
        import yaml
        with open(devices_yaml, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        return None, str(e)
    
    defaults = config.get('defaults', {})
    default_username = defaults.get('username', 'cumulus')
    
    devs = config.get('devices', {})
    if not devs:
        return None, 'No devices found in devices.yaml'
    
    devices = []
    for ip_addr, device_config in devs.items():
        if isinstance(device_config, str):
            match = re.match(r'^(.+?)\s+@(\w+)$', device_config.strip())
            if match:
                hostname = match.group(1).strip()
            else:
                hostname = device_config.strip()
            username = default_username
        elif isinstance(device_config, dict):
            hostname = device_config.get('hostname', str(ip_addr))
            username = device_config.get('username', default_username)
        else:
            continue
        devices.append({
            'ip': str(ip_addr),
            'hostname': hostname,
            'username': username
        })
    
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
action = post_data.get('action', 'setup')

def read_conf():
    """Read /etc/lldpq.conf into a dict (group-readable by www-data)."""
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

def write_conf(pairs):
    """Update key=value pairs in /etc/lldpq.conf as the lldpq user (root-owned file)."""
    if not pairs:
        return True
    keys_re = '|'.join(re.escape(k) for k in pairs)
    parts = ["sudo sed -i -E '/^(" + keys_re + ")=/d' /etc/lldpq.conf 2>/dev/null || true"]
    for k, v in pairs.items():
        parts.append('echo ' + shlex.quote(k + '=' + str(v)) + ' | sudo tee -a /etc/lldpq.conf >/dev/null')
    parts.append('sudo chown root:www-data /etc/lldpq.conf 2>/dev/null || true')
    parts.append('sudo chmod 664 /etc/lldpq.conf 2>/dev/null || true')
    try:
        r = subprocess.run(['sudo', '-u', lldpq_user, 'bash', '-c', ' && '.join(parts)],
                           capture_output=True, text=True, timeout=15)
        return r.returncode == 0
    except Exception:
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
    cmd = (
        f'cd {shlex.quote(lldpq_dir)} && : > .run.log && '
        f'nohup setsid bash -c "/usr/local/bin/lldpq - >> .run.log 2>&1; '
        f'echo __LLDPQ_DONE__ >> .run.log" >/dev/null 2>&1 &'
    )
    try:
        subprocess.Popen(['sudo', '-u', lldpq_user, 'bash', '-c', cmd],
                         start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(json.dumps({'success': True, 'message': 'LLDPq run started'}))
    except Exception as e:
        print(json.dumps({'success': False, 'error': str(e)}))
    sys.exit(0)

# ─── Action: Tail the run log started by action=run ───
if action == 'run-log':
    log_path = os.path.join(lldpq_dir, '.run.log')
    content = ''
    try:
        r = subprocess.run(['sudo', '-u', lldpq_user, 'cat', log_path],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            content = r.stdout
    except Exception:
        content = ''
    done = '__LLDPQ_DONE__' in content
    display = content.replace('__LLDPQ_DONE__', '').rstrip()
    print(json.dumps({'success': True, 'done': done, 'log': display}))
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
    SCRIPT = '''#!/usr/bin/env bash
source /etc/lldpq.conf 2>/dev/null
SRC="${LLDPQ_SRC:-}"
HOMESRC="$HOME/lldpq-src"
URL="__URL__"
LOG="__LOG__"
: > "$LOG"
{
  echo "=== LLDPq Update $(date) ==="
  if [ -n "$SRC" ] && [ -d "$SRC/.git" ]; then
    cd "$SRC" || exit 1
  elif [ -d "$HOMESRC/.git" ]; then
    cd "$HOMESRC" || exit 1
  else
    echo "Source repo not found (LLDPQ_SRC=$SRC); cloning $URL -> $HOMESRC"
    rm -rf "$HOMESRC"
    git clone "$URL" "$HOMESRC" && cd "$HOMESRC" || { echo "clone failed"; echo __LLDPQ_DONE__ >> "$LOG"; exit 1; }
  fi
  echo "--- git pull (in $(pwd)) ---"
  GIT_TERMINAL_PROMPT=0 timeout 120 git pull 2>&1 || echo "(git pull skipped/failed -- continuing with the current checkout)"
  echo "--- ./install.sh -y __BACKUP__ ---"
  ./install.sh -y __BACKUP__ 2>&1
  echo "--- install finished (exit $?) ---"
} >> "$LOG" 2>&1
echo __LLDPQ_DONE__ >> "$LOG"
'''
    log_path = os.path.join(state_dir, 'update.log')
    script = (SCRIPT.replace('__URL__', url)
              .replace('__BACKUP__', '--backup' if backup else '')
              .replace('__LOG__', log_path))
    try:
        w = subprocess.run(['sudo', '-u', lldpq_user, 'tee', script_path],
                           input=script, capture_output=True, text=True, timeout=10)
        if w.returncode != 0:
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
{
  echo "=== LLDPq Offline Update $(date) ==="
  echo "--- tarball: $TARBALL ---"
  if [ ! -f "$TARBALL" ]; then echo "ERROR: tarball not found (or not readable by $(whoami)): $TARBALL"; echo __LLDPQ_DONE__ >> "$LOG"; exit 1; fi
  TMP="$(mktemp -d)"
  echo "--- extracting ---"
  if ! tar -xzf "$TARBALL" -C "$TMP" 2>&1; then echo "ERROR: extract failed (is this a valid .tar.gz?)"; rm -rf "$TMP"; echo __LLDPQ_DONE__ >> "$LOG"; exit 1; fi
  INSTALLER="$(find "$TMP" -maxdepth 2 -name install.sh -type f 2>/dev/null | head -1)"
  if [ -z "$INSTALLER" ]; then echo "ERROR: install.sh not found inside the tarball"; rm -rf "$TMP"; echo __LLDPQ_DONE__ >> "$LOG"; exit 1; fi
  SRCDIR="$(dirname "$INSTALLER")"
  echo "--- source: $SRCDIR ---"
  if rm -rf "$DEST" && mkdir -p "$DEST" && cp -a "$SRCDIR/." "$DEST/"; then cd "$DEST" || cd "$SRCDIR"; else echo "(staging to $DEST failed; running from the extract dir)"; cd "$SRCDIR" || { echo __LLDPQ_DONE__ >> "$LOG"; exit 1; }; fi
  chmod +x ./install.sh 2>/dev/null
  echo "--- ./install.sh -y __BACKUP__ (offline) ---"
  ./install.sh -y __BACKUP__ 2>&1
  echo "--- install finished (exit $?) ---"
  rm -rf "$TMP"
} >> "$LOG" 2>&1
echo __LLDPQ_DONE__ >> "$LOG"
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
    done = '__LLDPQ_DONE__' in content
    display = content.replace('__LLDPQ_DONE__', '').rstrip()
    print(json.dumps({'success': True, 'done': done, 'log': display}))
    sys.exit(0)

# ─── Action: Read cron schedules for lldpq (auto-run) and get-conf (config collection) ───
if action == 'get-schedules':
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
    cron_file = '/etc/cron.d/lldpq' if os.path.exists('/etc/cron.d/lldpq') else '/etc/crontab'
    try:
        with open(cron_file) as f:
            orig = f.readlines()
    except Exception as e:
        print(json.dumps({'success': False, 'error': 'Cannot read ' + cron_file + ': ' + str(e)}))
        sys.exit(0)
    # Rebuild only the lldpq + get-conf lines (preserve every other line byte-for-byte).
    out = []
    for line in orig:
        parts = line.split()
        if (not line.lstrip().startswith('#')) and len(parts) >= 7 and parts[6] == '/usr/local/bin/lldpq':
            out.append(lldpq_cron + ' ' + ' '.join(parts[5:]) + '\n')
        elif (not line.lstrip().startswith('#')) and len(parts) >= 7 and parts[6] == '/usr/local/bin/get-conf':
            out.append(getconf_cron + ' ' + ' '.join(parts[5:]) + '\n')
        else:
            out.append(line)
    new_content = ''.join(out)
    tmp = os.path.join(lldpq_dir, '.cron.tmp')
    try:
        w = subprocess.run(['sudo', '-u', lldpq_user, 'tee', tmp], input=new_content,
                           capture_output=True, text=True, timeout=10)
        if w.returncode != 0:
            print(json.dumps({'success': False, 'error': 'Could not stage cron file'}))
            sys.exit(0)
        apply_cmd = (
            'sudo cp ' + shlex.quote(tmp) + ' ' + shlex.quote(cron_file) + ' && '
            'sudo chmod 644 ' + shlex.quote(cron_file) + ' && rm -f ' + shlex.quote(tmp) + ' && '
            "sudo sed -i '/^LLDPQ_CRON=/d;/^GETCONF_CRON=/d' /etc/lldpq.conf 2>/dev/null; "
            'echo ' + shlex.quote('LLDPQ_CRON="' + lldpq_cron + '"') + ' | sudo tee -a /etc/lldpq.conf >/dev/null; '
            'echo ' + shlex.quote('GETCONF_CRON="' + getconf_cron + '"') + ' | sudo tee -a /etc/lldpq.conf >/dev/null'
        )
        a = subprocess.run(['sudo', '-u', lldpq_user, 'bash', '-c', apply_cmd],
                           capture_output=True, text=True, timeout=20)
        if a.returncode != 0:
            print(json.dumps({'success': False, 'error': (a.stderr or 'apply failed').strip()[:200]}))
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
    import base64, io, tarfile, time as _t
    include_key = bool(post_data.get('include_key'))
    wanted = [('devices.yaml', lldpq_dir), ('topology.dot', lldpq_dir),
              ('topology_config.yaml', lldpq_dir), ('notifications.yaml', lldpq_dir),
              ('display-aliases.json', web_root)]
    buf = io.BytesIO()
    added = []
    has_key = False
    try:
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for fn, base_dir in wanted:
                p = os.path.join(base_dir, fn)
                if os.path.isfile(p):
                    tar.add(p, arcname=fn)
                    added.append(fn)
            # Collector SSH key (private + public). Opt-in — makes the bundle SECRET, but lets a
            # restore reach the switches immediately (true "move to another host" bundle).
            if include_key:
                for key_name in ('id_ed25519', 'id_rsa'):
                    kp = os.path.expanduser('~%s/.ssh/%s' % (lldpq_user, key_name))
                    r = subprocess.run(['sudo', '-u', lldpq_user, 'cat', kp], capture_output=True, timeout=5)
                    if r.returncode == 0 and b'PRIVATE KEY' in r.stdout:
                        ti = tarfile.TarInfo('ssh/%s' % key_name); ti.size = len(r.stdout); ti.mode = 0o600
                        tar.addfile(ti, io.BytesIO(r.stdout)); added.append('ssh/%s' % key_name); has_key = True
                        rp = subprocess.run(['sudo', '-u', lldpq_user, 'cat', kp + '.pub'], capture_output=True, timeout=5)
                        if rp.returncode == 0 and rp.stdout.strip():
                            tip = tarfile.TarInfo('ssh/%s.pub' % key_name); tip.size = len(rp.stdout); tip.mode = 0o644
                            tar.addfile(tip, io.BytesIO(rp.stdout)); added.append('ssh/%s.pub' % key_name)
                        break
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
    import base64, io, tarfile
    b64 = post_data.get('data', '')
    if not b64:
        print(json.dumps({'success': False, 'error': 'No file data'}))
        sys.exit(0)
    try:
        raw = base64.b64decode(b64)
    except Exception:
        print(json.dumps({'success': False, 'error': 'Invalid file (not base64)'}))
        sys.exit(0)
    allowed = {'devices.yaml': lldpq_dir, 'topology.dot': lldpq_dir,
               'topology_config.yaml': lldpq_dir, 'notifications.yaml': lldpq_dir,
               'display-aliases.json': web_root}
    key_names = {'id_ed25519', 'id_ed25519.pub', 'id_rsa', 'id_rsa.pub'}
    ssh_dir = os.path.expanduser('~%s/.ssh' % lldpq_user)
    restored = []
    keys = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
            for m in tar.getmembers():
                if not m.isfile():
                    continue
                name = m.name.replace('\\', '/')
                base = os.path.basename(name)
                # SSH key files (ssh/id_ed25519[.pub]) -> service user's ~/.ssh with strict perms
                if name.startswith('ssh/') and base in key_names:
                    content = tar.extractfile(m).read()
                    subprocess.run(['sudo', '-u', lldpq_user, 'mkdir', '-p', ssh_dir], capture_output=True, timeout=10)
                    dest = os.path.join(ssh_dir, base)
                    w = subprocess.run(['sudo', '-u', lldpq_user, 'tee', dest],
                                       input=content, capture_output=True, timeout=10)
                    if w.returncode == 0:
                        mode = '644' if base.endswith('.pub') else '600'
                        subprocess.run(['sudo', '-u', lldpq_user, 'bash', '-c',
                                        'chmod %s %s' % (mode, shlex.quote(dest))], capture_output=True, timeout=10)
                        keys.append(base)
                    continue
                # Config files
                if base in allowed:
                    content = tar.extractfile(m).read()
                    dest = os.path.join(allowed[base], base)
                    w = subprocess.run(['sudo', '-u', lldpq_user, 'tee', dest],
                                       input=content, capture_output=True, timeout=15)
                    if w.returncode == 0:
                        restored.append(base)
    except Exception as e:
        print(json.dumps({'success': False, 'error': 'Not a valid LLDPq config bundle: ' + str(e)[:150]}))
        sys.exit(0)
    if not restored and not keys:
        print(json.dumps({'success': False, 'error': 'No recognized config files inside the archive.'}))
        sys.exit(0)
    print(json.dumps({'success': True, 'restored': restored, 'keys': keys}))
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
