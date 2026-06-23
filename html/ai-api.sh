#!/bin/bash
# ai-api.sh - AI Assistant API
# Backend for ai.html — LLM proxy with fabric context
# Called by nginx fcgiwrap

# Load config
if [[ -f /etc/lldpq.conf ]]; then
    source /etc/lldpq.conf
fi

LLDPQ_DIR="${LLDPQ_DIR:-/home/lldpq/lldpq}"
LLDPQ_USER="${LLDPQ_USER:-lldpq}"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"

# AI config
AI_PROVIDER="${AI_PROVIDER:-ollama}"
AI_MODEL="${AI_MODEL:-llama3.2}"
AI_API_KEY="${AI_API_KEY:-}"
AI_API_URL="${AI_API_URL:-https://api.openai.com/v1}"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
AI_PROXY_URL="${AI_PROXY_URL:-}"
# Optional web-research model (OpenAI-compatible, e.g. a Perplexity/Sonar model on the
# NVIDIA inference proxy). Empty = [SEARCH:] tool disabled. URL/key default to AI_API_*.
AI_SEARCH_MODEL="${AI_SEARCH_MODEL:-}"
AI_SEARCH_URL="${AI_SEARCH_URL:-}"
AI_SEARCH_KEY="${AI_SEARCH_KEY:-}"

# Parse query string
ACTION=$(echo "$QUERY_STRING" | grep -oP 'action=\K[^&]*' | head -1)

source "$(dirname "$0")/auth-guard.sh"
# AI Assistant is admin-only — operators cannot access any AI action
require_admin

# All responses are JSON (SSE streaming not supported by fcgiwrap)
echo "Content-Type: application/json"
echo ""

# Read POST data
POST_DATA=""
if [ "$REQUEST_METHOD" = "POST" ] && [ -n "$CONTENT_LENGTH" ] && [ "$CONTENT_LENGTH" -gt 0 ] 2>/dev/null; then
    POST_DATA=$(dd bs=4096 count=$(( (CONTENT_LENGTH + 4095) / 4096 )) 2>/dev/null | head -c "$CONTENT_LENGTH")
fi

# Export for Python
export LLDPQ_DIR LLDPQ_USER WEB_ROOT
export AI_PROVIDER AI_MODEL AI_API_KEY AI_API_URL OLLAMA_URL AI_PROXY_URL
export AI_SEARCH_MODEL AI_SEARCH_URL AI_SEARCH_KEY
export POST_DATA ACTION

python3 << 'PYTHON_SCRIPT'
import json
import sys
import os
import re
import time
import glob

ACTION = os.environ.get('ACTION', '')
POST_DATA = os.environ.get('POST_DATA', '')
LLDPQ_DIR = os.environ.get('LLDPQ_DIR', '/home/lldpq/lldpq')
LLDPQ_USER = os.environ.get('LLDPQ_USER', 'lldpq')
WEB_ROOT = os.environ.get('WEB_ROOT', '/var/www/html')
AI_PROVIDER = os.environ.get('AI_PROVIDER', 'ollama')
AI_MODEL = os.environ.get('AI_MODEL', 'llama3.2')
AI_API_KEY = os.environ.get('AI_API_KEY', '')
AI_API_URL = os.environ.get('AI_API_URL', 'https://api.openai.com/v1')
OLLAMA_URL = os.environ.get('OLLAMA_URL', 'http://localhost:11434')
AI_PROXY_URL = os.environ.get('AI_PROXY_URL', '')
# Web-research model (OpenAI-compatible). URL/key fall back to the main AI endpoint.
AI_SEARCH_MODEL = os.environ.get('AI_SEARCH_MODEL', '')
AI_SEARCH_URL = os.environ.get('AI_SEARCH_URL', '') or AI_API_URL
AI_SEARCH_KEY = os.environ.get('AI_SEARCH_KEY', '') or AI_API_KEY
SEARCH_ENABLED = bool(AI_SEARCH_MODEL)

# Set HTTP proxy if configured (allows airgapped servers to reach cloud APIs via SSH tunnel)
if AI_PROXY_URL:
    os.environ['http_proxy'] = AI_PROXY_URL
    os.environ['https_proxy'] = AI_PROXY_URL

ANALYSIS_FILE = os.path.join(WEB_ROOT, 'ai-analysis.json')

AI_FALLBACK_MODEL = os.environ.get('AI_FALLBACK_MODEL', '')
# Cloud providers receive a redacted copy of the context (secrets stripped); local ollama does not.
IS_CLOUD_PROVIDER = AI_PROVIDER != 'ollama'

_SECRET_RE = re.compile(
    r'(?i)\b(password|passwd|secret|community|key-string|psk|pre-?shared-?key|md5|'
    r'auth-?key|priv-?key|snmp-community|wpa-psk|api[-_]?key|token)\b(\s*[:=]?\s+)(\S+)'
)


def redact_secrets(text):
    """Strip credential-like values (passwords, keys, community strings, private-key blocks)
    so they are never sent to a cloud LLM."""
    if not text:
        return text
    text = _SECRET_RE.sub(lambda m: "%s%s***REDACTED***" % (m.group(1), m.group(2)), text)
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----',
                  '***PRIVATE KEY REDACTED***', text, flags=re.DOTALL)
    return text


def maybe_redact(text):
    return redact_secrets(text) if IS_CLOUD_PROVIDER else text


def result_json(data):
    print(json.dumps(data))
    sys.exit(0)

def error_json(msg):
    result_json({"success": False, "error": msg})

def sse_event(data, event=None):
    """Send a Server-Sent Event."""
    if event:
        sys.stdout.write(f"event: {event}\n")
    sys.stdout.write(f"data: {json.dumps(data)}\n\n")
    sys.stdout.flush()

# ======================== CONTEXT BUILDER ========================

def build_fabric_summary():
    """Build a structured fabric summary from all LLDPq data sources."""
    summary = []
    
    # 1. Device inventory
    devices = {}
    roles = {}
    try:
        devices_file = os.path.join(LLDPQ_DIR, 'devices.yaml')
        if os.path.exists(devices_file):
            import yaml
            with open(devices_file, 'r') as f:
                data = yaml.safe_load(f) or {}
            section = data.get('devices', data)
            if isinstance(section, dict):
                for ip, info in section.items():
                    if ip in ('defaults', 'endpoint_hosts'):
                        continue
                    if isinstance(info, str):
                        m = re.match(r'^(.+?)\s+@(\w+)$', info.strip())
                        hostname = m.group(1).strip() if m else info.strip()
                        role = m.group(2).lower() if m else 'unknown'
                    elif isinstance(info, dict):
                        hostname = info.get('hostname', str(ip))
                        role = info.get('role', 'unknown').lower()
                    else:
                        hostname = str(ip)
                        role = 'unknown'
                    devices[str(ip)] = {'hostname': hostname, 'role': role, 'ip': str(ip)}
                    roles[role] = roles.get(role, 0) + 1
    except Exception:
        pass
    
    role_summary = ', '.join(f"{count} {role}" for role, count in sorted(roles.items(), key=lambda x: -x[1]))
    summary.append(f"DEVICE INVENTORY: {len(devices)} devices ({role_summary})")
    
    # 2. Device cache (health info)
    device_health = {}
    try:
        cache_file = os.path.join(WEB_ROOT, 'device-cache.json')
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                cache = json.load(f)
            if isinstance(cache, dict):
                for hostname, info in cache.items():
                    if isinstance(info, dict):
                        device_health[hostname] = {
                            'ip': info.get('ip', ''),
                            'mac': info.get('mac', ''),
                            'release': info.get('release', ''),
                            'uptime': info.get('uptime', ''),
                            'model': info.get('model', ''),
                            'status': info.get('status', ''),
                            'last_seen': info.get('last_seen', ''),
                        }
    except Exception:
        pass
    
    online = sum(1 for d in device_health.values() if d.get('status') == 'ok')
    summary.append(f"HEALTH: {online}/{len(device_health)} devices responding")
    
    # 3. LLDP status
    lldp_problems = 0
    lldp_total = 0
    try:
        lldp_file = os.path.join(WEB_ROOT, 'lldp_results.ini')
        if os.path.exists(lldp_file):
            with open(lldp_file, 'r') as f:
                for line in f:
                    if 'Pass' in line or 'Fail' in line or 'No-Info' in line:
                        lldp_total += 1
                    if 'Fail' in line:
                        lldp_problems += 1
    except Exception:
        pass
    
    problems_file = os.path.join(WEB_ROOT, 'problems-lldp_results.ini')
    problem_details = []
    try:
        if os.path.exists(problems_file):
            with open(problems_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and not line.startswith('['):
                        problem_details.append(line)
    except Exception:
        pass
    
    summary.append(f"LLDP: {lldp_total} links checked, {lldp_problems} problems")
    if problem_details:
        summary.append(f"LLDP PROBLEMS:\n" + '\n'.join(problem_details[:20]))
    
    # 4. BGP history
    try:
        bgp_file = os.path.join(LLDPQ_DIR, 'monitor-results', 'bgp_history.json')
        if os.path.exists(bgp_file):
            with open(bgp_file, 'r') as f:
                bgp = json.load(f)
            total_sessions = 0
            down_sessions = []
            for device, neighbors in bgp.items():
                if isinstance(neighbors, dict):
                    for neighbor, info in neighbors.items():
                        if isinstance(info, dict):
                            total_sessions += 1
                            state = info.get('state', '')
                            if state and state.lower() != 'established':
                                down_sessions.append(f"{device} → {neighbor}: {state}")
            summary.append(f"BGP: {total_sessions} sessions, {len(down_sessions)} not established")
            if down_sessions:
                summary.append("BGP ISSUES:\n" + '\n'.join(down_sessions[:10]))
    except Exception:
        pass
    
    # 5. Log summary (totals + per-device critical breakdown)
    try:
        log_file = os.path.join(LLDPQ_DIR, 'monitor-results', 'log_summary.json')
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = json.load(f)
            critical = sum(d.get('critical', 0) for d in logs.values() if isinstance(d, dict))
            errors = sum(d.get('error', 0) for d in logs.values() if isinstance(d, dict))
            warnings = sum(d.get('warning', 0) for d in logs.values() if isinstance(d, dict))
            if critical or errors or warnings:
                summary.append(f"LOGS: {critical} critical, {errors} errors, {warnings} warnings across all devices")
            if critical > 0:
                crit_devices = []
                device_counts = logs.get('device_counts', logs)
                for dev, counts in sorted(device_counts.items()):
                    if isinstance(counts, dict) and counts.get('critical', 0) > 0:
                        crit_devices.append(f"  {dev}: {counts['critical']} critical")
                if crit_devices:
                    summary.append("CRITICAL LOG DEVICES:\n" + "\n".join(crit_devices[:20]))
            
            recent = logs.get('recent_messages', {})
            if recent:
                log_lines = []
                for dev in sorted(recent.keys())[:5]:
                    for msg in recent[dev][:2]:
                        log_lines.append(f"  {dev}: {msg}")
                if log_lines:
                    summary.append("LOG SAMPLES (top 5 devices, use Attach Logs button for full detail):\n" + "\n".join(log_lines))
    except Exception:
        pass
    
    # 6. Discovery status
    try:
        disc_file = os.path.join(WEB_ROOT, 'discovery-cache.json')
        if os.path.exists(disc_file):
            with open(disc_file, 'r') as f:
                disc = json.load(f)
            entries = disc.get('entries', [])
            provisioned = sum(1 for e in entries if e.get('device_type') == 'provisioned')
            not_prov = sum(1 for e in entries if e.get('device_type') == 'not_provisioned')
            unreachable = sum(1 for e in entries if e.get('device_type') == 'unreachable')
            other = sum(1 for e in entries if e.get('device_type') == 'other')
            mismatches = sum(1 for e in entries if e.get('mac_status') == 'mismatch')
            age = int(time.time() - disc.get('timestamp', 0))
            age_str = f"{age//60}m ago" if age < 3600 else f"{age//3600}h ago"
            summary.append(f"DISCOVERY ({age_str}): {provisioned} provisioned, {not_prov} no-key, {unreachable} unreachable, {other} other")
            if mismatches:
                summary.append(f"  MAC MISMATCHES: {mismatches}")
    except Exception:
        pass
    
    # 7. Fabric tables summary
    try:
        tables_dir = os.path.join(LLDPQ_DIR, 'monitor-results', 'fabric-tables')
        summary_file = os.path.join(tables_dir, 'summary.json')
        if os.path.exists(summary_file):
            with open(summary_file, 'r') as f:
                fsummary = json.load(f)
            arp_count = fsummary.get('arp_count', 0)
            mac_count = fsummary.get('mac_count', 0)
            vtep_count = fsummary.get('vtep_count', 0)
            summary.append(f"FABRIC TABLES: {arp_count} ARP entries, {mac_count} MAC entries, {vtep_count} VTEPs")
    except Exception:
        pass
    
    return '\n'.join(summary), devices, device_health


def build_device_detail(hostname, devices, device_health):
    """Build detailed info for a specific device."""
    detail = []
    ip = ''
    
    # Find IP from devices dict
    for dev_ip, dev_info in devices.items():
        if dev_info['hostname'] == hostname or dev_ip == hostname:
            ip = dev_ip
            hostname = dev_info['hostname']
            detail.append(f"DEVICE: {hostname} ({ip}) role={dev_info['role']}")
            break
    
    if not ip:
        return f"Device '{hostname}' not found in inventory."
    
    # Health info
    health = device_health.get(hostname, {})
    if health:
        detail.append(f"  Model: {health.get('model', '?')}, Release: {health.get('release', '?')}, Uptime: {health.get('uptime', '?')}")
        detail.append(f"  MAC: {health.get('mac', '?')}, Status: {health.get('status', '?')}, Last seen: {health.get('last_seen', '?')}")
    
    # Fabric table for this device
    try:
        table_file = os.path.join(LLDPQ_DIR, 'monitor-results', 'fabric-tables', f'{hostname}.json')
        if os.path.exists(table_file):
            with open(table_file, 'r') as f:
                table = json.load(f)
            arp = table.get('arp', [])
            mac = table.get('mac', [])
            lldp = table.get('lldp', [])
            bonds = table.get('bonds', [])
            routes = table.get('routes', [])
            detail.append(f"  ARP: {len(arp)} entries, MAC: {len(mac)} entries, LLDP neighbors: {len(lldp)}")
            if lldp:
                detail.append("  LLDP NEIGHBORS:")
                for n in lldp[:20]:
                    detail.append(f"    {n.get('local_port', '?')} → {n.get('neighbor', '?')} ({n.get('neighbor_port', '?')})")
            if bonds:
                detail.append(f"  BONDS: {len(bonds)}")
            if routes:
                detail.append(f"  ROUTES: {len(routes)} entries")
    except Exception:
        pass
    
    # BGP for this device
    try:
        bgp_file = os.path.join(LLDPQ_DIR, 'monitor-results', 'bgp_history.json')
        if os.path.exists(bgp_file):
            with open(bgp_file, 'r') as f:
                bgp = json.load(f)
            dev_bgp = bgp.get(hostname, {})
            if dev_bgp:
                detail.append(f"  BGP NEIGHBORS: {len(dev_bgp)}")
                for neighbor, info in list(dev_bgp.items())[:20]:
                    if isinstance(info, dict):
                        state = info.get('state', '?')
                        pfx = info.get('prefixes', '?')
                        detail.append(f"    {neighbor}: {state} (prefixes: {pfx})")
    except Exception:
        pass
    
    return '\n'.join(detail) if detail else f"Device '{hostname}' found but no detailed data available."


def read_collected_config(hostname, max_chars=15000):
    """Full collected running config for one device (nv config show -o commands),
    saved by get-configs.sh at WEB_ROOT/configs/<hostname>.txt."""
    try:
        path = os.path.join(WEB_ROOT, 'configs', f'{hostname}.txt')
        if not os.path.isfile(path):
            return ''
        with open(path, 'r') as f:
            cfg = f.read().strip()
        if not cfg:
            return ''
        if len(cfg) > max_chars:
            cfg = cfg[:max_chars] + f"\n... (truncated; {len(cfg)} chars total)"
        return f"FULL RUNNING CONFIG -- {hostname} (nv config show -o commands):\n{cfg}"
    except Exception:
        return ''


def build_all_collected_configs(devices=None, max_per_device=2500, max_total=120000):
    """Every collected running config on disk (truncated per device) for fabric-wide
    config analysis / drift detection. Reads WEB_ROOT/configs/*.txt DIRECTLY so it works
    even when devices.yaml hostnames differ from the collected config filenames."""
    config_dir = os.path.join(WEB_ROOT, 'configs')
    if not os.path.isdir(config_dir):
        return ''
    out, total = [], 0
    for path in sorted(glob.glob(os.path.join(config_dir, '*.txt'))):
        hn = os.path.basename(path)[:-4]  # strip .txt
        try:
            with open(path, 'r') as f:
                cfg = f.read().strip()
        except Exception:
            continue
        if not cfg:
            continue
        block = cfg[:max_per_device]
        if len(cfg) > max_per_device:
            block += f"\n... (truncated; {len(cfg)} total)"
        entry = f"----- {hn} -----\n{block}"
        if total + len(entry) > max_total:
            out.append("... (remaining device configs omitted for length)")
            break
        out.append(entry)
        total += len(entry)
    if not out:
        return ''
    return ("FULL COLLECTED RUNNING CONFIGS (all devices, nv config show -o commands; "
            "truncated per device):\n\n" + "\n\n".join(out))


def _mr_path(*parts):
    """Resolve a monitor-results file, preferring LLDPQ_DIR then the synced WEB_ROOT copy."""
    p1 = os.path.join(LLDPQ_DIR, 'monitor-results', *parts)
    if os.path.exists(p1):
        return p1
    return os.path.join(WEB_ROOT, 'monitor-results', *parts)


def _load_json_file(path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception:
        return None


def _save_json_web(path, data):
    """Write JSON under WEB_ROOT, falling back to sudo tee when www-data can't write."""
    txt = json.dumps(data, indent=2)
    try:
        with open(path, 'w') as f:
            f.write(txt)
    except PermissionError:
        import subprocess
        subprocess.run(['sudo', '-n', 'tee', path], input=txt, capture_output=True, text=True, timeout=10)
        subprocess.run(['sudo', '-n', 'chown', f'{LLDPQ_USER}:www-data', path], capture_output=True, timeout=5)
        subprocess.run(['sudo', '-n', 'chmod', '664', path], capture_output=True, timeout=5)


# ======================== MEMORY (operator-taught learnings) ==================
# Persistent site-specific facts the operator teaches ("remember: ..."). Injected
# into the prompt context so the AI learns this fabric's quirks across sessions.
LEARNINGS_FILE = os.path.join(WEB_ROOT, 'ai-learnings.json')

def load_learnings():
    try:
        with open(LEARNINGS_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, list) else []
    except Exception:
        return []

def save_learnings(items):
    clean, seen = [], set()
    for it in (items or [])[:500]:
        t = (it.get('text') if isinstance(it, dict) else str(it)).strip()
        if t and t.lower() not in seen and len(t) <= 400:
            seen.add(t.lower())
            ts = (it.get('ts') if isinstance(it, dict) else None) or int(time.time())
            clean.append({'text': t, 'ts': ts})
    _save_json_web(LEARNINGS_FILE, clean)
    return clean

def add_learning(text):
    text = (text or '').strip()
    if not text:
        return False
    items = load_learnings()
    if any(it.get('text', '').lower() == text.lower() for it in items):
        return True
    items.append({'text': text[:400], 'ts': int(time.time())})
    save_learnings(items)
    return True

def relevant_learnings(question, cap=30):
    """All learnings if few; otherwise the ones sharing words with the question."""
    items = load_learnings()
    texts = [it.get('text', '') for it in items if it.get('text')]
    if not texts:
        return ''
    if len(texts) > cap:
        qwords = set(re.findall(r'[A-Za-z0-9_.-]{3,}', (question or '').lower()))
        scored = [(len(qwords & set(re.findall(r'[A-Za-z0-9_.-]{3,}', t.lower()))), i, t)
                  for i, t in enumerate(texts)]
        scored.sort(key=lambda x: (-x[0], -x[1]))
        texts = [t for _, _, t in scored[:cap]]
    return '\n'.join('- ' + t for t in texts)


# ======================== WEB RESEARCH ([SEARCH:]) ============================
def run_search(query):
    """Web research via a configured search-capable model (OpenAI-compatible)."""
    query = (query or '').strip()
    if not SEARCH_ENABLED:
        return "Web search is not configured (set AI_SEARCH_MODEL)."
    if not query:
        return "Empty search query."
    import urllib.request
    url = f"{AI_SEARCH_URL}/chat/completions"
    msgs = [
        {"role": "system", "content": "You are a network research assistant. Answer concisely "
         "using current web sources, focused on NVIDIA Cumulus Linux / networking known issues, "
         "release notes, CVEs and advisories. Always include source URLs."},
        {"role": "user", "content": query},
    ]
    payload = json.dumps({"model": AI_SEARCH_MODEL, "messages": msgs}).encode()
    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {AI_SEARCH_KEY}'}
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        resp = urllib.request.urlopen(req, timeout=70)
        result = json.loads(resp.read().decode())
        return (result.get('choices', [{}])[0].get('message', {}).get('content', '') or '(no result)')[:4000]
    except Exception as e:
        return f"Search error: {e}"


def _health_snapshot(devices, device_health):
    """Per-device status map for run-to-run change detection (defensive about shapes)."""
    snap = {}
    for ip, dev in (devices or {}).items():
        hn = dev.get('hostname')
        if not hn:
            continue
        h = (device_health or {}).get(hn) or (device_health or {}).get(ip) or {}
        snap[hn] = (h.get('status') if isinstance(h, dict) else None) or dev.get('status') or 'unknown'
    return snap


def _diff_snapshots(prev, cur):
    """List human-readable status changes between two snapshots."""
    changes = []
    for hn, st in cur.items():
        p = prev.get(hn)
        if p is None:
            changes.append("NEW device %s (%s)" % (hn, st))
        elif p != st:
            changes.append("%s: %s -> %s" % (hn, p, st))
    for hn, p in prev.items():
        if hn not in cur:
            changes.append("REMOVED device %s (was %s)" % (hn, p))
    return changes


def build_transceiver_context(hosts=None, max_chars=9000):
    """Transceiver inventory: per-module vendor/part/serial/FW + status, plus summary."""
    inv = _load_json_file(_mr_path('transceiver_inventory.json'))
    if not inv or not inv.get('modules'):
        return ''
    mods = [m for m in inv['modules'] if (not hosts or m.get('device') in hosts)]
    if not mods:
        return ''
    lines = ["TRANSCEIVER INVENTORY (device/port: vendor part sn fw [fw_status]):"]
    for m in mods[:250]:
        lines.append(f"  {m.get('device','?')}/{m.get('port','?')}: {m.get('vendor','')} "
                     f"{m.get('part_number','')} sn={m.get('serial','')} fw={m.get('fw_version','')} "
                     f"[{m.get('fw_status','')}]")
    s = inv.get('summary') or {}
    if s:
        lines.append(f"  SUMMARY: {s.get('total_modules')} modules, {s.get('unique_models')} models, "
                     f"mixed-fw={s.get('mixed_fw_models')}, status={s.get('status_counts')}")
    return '\n'.join(lines)[:max_chars]


def build_optical_context(hosts=None, max_chars=9000):
    """Optical DOM per port: health, Rx/Tx power, temperature, voltage, bias, link margin."""
    stats = (_load_json_file(_mr_path('optical_history.json')) or {}).get('current_optical_stats') or {}
    if not stats:
        return ''
    lines = ["OPTICAL DOM (host:port: health rx_dBm tx_dBm temp_C volt bias_mA margin_dB):"]
    for key in sorted(stats):
        if hosts and key.split(':')[0] not in hosts:
            continue
        v = stats[key]
        lines.append(f"  {key}: {v.get('health_status','')} rx={v.get('rx_power_dbm','')} "
                     f"tx={v.get('tx_power_dbm','')} temp={v.get('temperature_c','')} "
                     f"v={v.get('voltage_v','')} bias={v.get('bias_current_ma','')} "
                     f"margin={v.get('link_margin_db','')}")
    return '\n'.join(lines)[:max_chars] if len(lines) > 1 else ''


def build_ber_context(hosts=None, max_chars=9000):
    """Per-port BER / interface errors: ber value, grade, rx/tx errors, total packets, deltas."""
    stats = (_load_json_file(_mr_path('ber_history.json')) or {}).get('current_ber_stats') or {}
    if not stats:
        return ''
    lines = ["BER / INTERFACE ERRORS (host:port: ber grade rxErr txErr totalPkt dErr):"]
    for key in sorted(stats):
        if hosts and key.split(':')[0] not in hosts:
            continue
        v = stats[key]
        lines.append(f"  {key}: ber={v.get('ber_value','')} grade={v.get('grade','')} "
                     f"rxErr={v.get('rx_errors','')} txErr={v.get('tx_errors','')} "
                     f"totalPkt={v.get('total_packets','')} dErr={v.get('delta_errors','')}")
    return '\n'.join(lines)[:max_chars] if len(lines) > 1 else ''


def build_hardware_context(hosts=None, max_chars=9000):
    """Per-device hardware: sensors/thermal/PSU/fan/memory/load (raw collected text)."""
    hw_dir = _mr_path('hardware-data')
    if not os.path.isdir(hw_dir):
        return ''
    out, total = ["HARDWARE (per-device sensors/thermal/PSU/fan/mem/load):"], 0
    for f in sorted(glob.glob(os.path.join(hw_dir, '*_hardware.txt'))):
        host = os.path.basename(f).replace('_hardware.txt', '')
        if hosts and host not in hosts:
            continue
        try:
            with open(f, 'r') as fh:
                content = fh.read().strip()
        except Exception:
            continue
        if not content:
            continue
        block = f"--- {host} ---\n{content[:1400]}"
        if total + len(block) > max_chars:
            out.append("... (more devices omitted)")
            break
        out.append(block)
        total += len(block)
    return '\n\n'.join(out) if len(out) > 1 else ''


def build_context_for_question(question, devices, device_health):
    """Build targeted context based on the question content."""
    extra_context = []
    q_lower = question.lower()
    mentioned_any = False
    mentioned_hosts = []

    # Operator-taught site facts (memory) — trust these as ground truth.
    _lr = relevant_learnings(question)
    if _lr:
        extra_context.append("OPERATOR-TAUGHT FACTS (site-specific; trust these):\n" + _lr)
    
    # Detect specific device mentions
    for ip, dev in devices.items():
        if dev['hostname'].lower() in q_lower or ip in q_lower:
            mentioned_any = True
            mentioned_hosts.append(dev['hostname'])
            extra_context.append(build_device_detail(dev['hostname'], devices, device_health))
            _cfg = read_collected_config(dev['hostname'])
            if _cfg:
                extra_context.append(_cfg)
    
    # Keyword-based enrichment
    if any(kw in q_lower for kw in ['flap', 'down', 'carrier', 'link down']):
        try:
            flap_dir = os.path.join(LLDPQ_DIR, 'monitor-results', 'flap-data')
            if os.path.isdir(flap_dir):
                flaps = []
                for f in sorted(glob.glob(os.path.join(flap_dir, '*.txt')))[-10:]:
                    with open(f, 'r') as fh:
                        content = fh.read().strip()
                        if content:
                            flaps.append(f"--- {os.path.basename(f)} ---\n{content[:500]}")
                if flaps:
                    extra_context.append("LINK FLAP DATA:\n" + '\n'.join(flaps))
        except Exception:
            pass
    
    if any(kw in q_lower for kw in ['vlan', 'vxlan', 'evpn']):
        try:
            for profile_name in ['vlan_profiles.yaml', 'sw_port_profiles.yaml']:
                for root in [os.path.join(LLDPQ_DIR, '..'), '/var/www']:
                    for dirpath, dirnames, filenames in os.walk(root):
                        if profile_name in filenames:
                            filepath = os.path.join(dirpath, profile_name)
                            with open(filepath, 'r') as f:
                                content = f.read()[:2000]
                            extra_context.append(f"{profile_name}:\n{content}")
                            break
        except Exception:
            pass
    
    if any(kw in q_lower for kw in ['topology', 'connection', 'cable', 'wiring', 'link']):
        try:
            topo_file = os.path.join(WEB_ROOT, 'topology.dot')
            if os.path.exists(topo_file):
                with open(topo_file, 'r') as f:
                    content = f.read()[:3000]
                extra_context.append(f"TOPOLOGY (DOT):\n{content}")
        except Exception:
            pass
    
    # Config check: load Ansible host_vars + group_vars for config consistency analysis
    if any(kw in q_lower for kw in ['config', 'consistency', 'check', 'asn', 'mtu', 'mismatch', 'validate', 'audit', 'compare', 'bgp config', 'vlan config']):
        extra_context.append(build_config_context(devices))
        # Fabric-wide config question (no specific device named) -> feed every device's
        # actual running config so the model can do real drift/consistency analysis.
        if not mentioned_any:
            _allcfg = build_all_collected_configs(devices)
            if _allcfg:
                extra_context.append(_allcfg)
    
    # Other collected data (transceiver / optical / BER / hardware). Filtered to the
    # mentioned device(s) when named, otherwise fabric-wide.
    _hf = mentioned_hosts or None
    if any(kw in q_lower for kw in ['transceiver', 'optic', 'optical', 'optik', 'sfp', 'qsfp', 'osfp',
                                    'dom', 'module', 'modul', 'firmware', 'fw version', 'fiber', 'fibre',
                                    'pluggable', 'gbic', 'dbm', 'margin', 'rx power', 'tx power', 'light',
                                    'isik', 'ışık', 'optigi', 'optiği']):
        for _b in (build_transceiver_context(_hf), build_optical_context(_hf)):
            if _b:
                extra_context.append(_b)
    if any(kw in q_lower for kw in ['ber', 'fec', 'crc', 'fcs', 'symbol', 'bit error', 'errored', 'rx error',
                                    'tx error', 'corrupt', 'error', 'hata', 'discard', 'drop', 'dropped',
                                    'paket', 'packet']):
        _b = build_ber_context(_hf)
        if _b:
            extra_context.append(_b)
    if any(kw in q_lower for kw in ['hardware', 'donanim', 'donanım', 'sensor', 'sensör', 'temperature',
                                    'temp', 'sicaklik', 'sıcaklık', 'thermal', 'psu', 'power supply', 'fan',
                                    'cpu', 'memory', 'bellek', 'voltage', 'voltaj', 'health', 'saglik', 'sağlık']):
        _b = build_hardware_context(_hf)
        if _b:
            extra_context.append(_b)
    
    return '\n\n'.join(extra_context)


def build_config_context(devices):
    """Load Ansible config data for consistency checking."""
    import subprocess
    lines = []
    
    # Find Ansible dir from lldpq.conf
    ansible_dir = ''
    try:
        with open('/etc/lldpq.conf', 'r') as f:
            for line in f:
                if line.startswith('ANSIBLE_DIR='):
                    ansible_dir = line.strip().split('=', 1)[1]
                    break
    except Exception:
        pass
    
    if not ansible_dir or ansible_dir == 'NoNe' or not os.path.isdir(ansible_dir):
        return "CONFIG DATA: No Ansible directory configured. Cannot check config consistency."
    
    host_vars_dir = os.path.join(ansible_dir, 'inventory', 'host_vars')
    group_vars_dir = os.path.join(ansible_dir, 'inventory', 'group_vars', 'all')
    
    # 1. Load group_vars (shared config: VLANs, port profiles, BGP profiles)
    for profile in ['vlan_profiles.yaml', 'sw_port_profiles.yaml', 'bgp_profiles.yaml']:
        filepath = os.path.join(group_vars_dir, profile)
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    content = f.read()[:2000]
                lines.append(f"--- {profile} (shared config) ---\n{content}")
            except Exception:
                pass
    
    # 2. Load host_vars for each device (per-device config)
    # Extract key fields: BGP ASN, interfaces, MTU, VRFs, bonds, EVPN
    device_configs = {}
    if os.path.isdir(host_vars_dir):
        for fname in sorted(os.listdir(host_vars_dir)):
            if not fname.endswith('.yaml') and not fname.endswith('.yml'):
                continue
            hostname = fname.rsplit('.', 1)[0]
            filepath = os.path.join(host_vars_dir, fname)
            try:
                import yaml
                with open(filepath, 'r') as f:
                    cfg = yaml.safe_load(f) or {}
                
                # Extract key config fields for comparison
                summary = {}
                if 'bgp' in cfg:
                    bgp = cfg['bgp']
                    summary['asn'] = bgp.get('asn', '?')
                    summary['router_id'] = bgp.get('router_id', '?')
                    neighbors = bgp.get('neighbors', {})
                    summary['bgp_neighbors'] = len(neighbors) if isinstance(neighbors, dict) else 0
                
                if 'interfaces' in cfg:
                    ifaces = cfg['interfaces']
                    mtus = set()
                    for iface_name, iface_cfg in ifaces.items() if isinstance(ifaces, dict) else []:
                        if isinstance(iface_cfg, dict):
                            mtu = iface_cfg.get('mtu')
                            if mtu:
                                mtus.add(str(mtu))
                    if mtus:
                        summary['mtus'] = list(mtus)
                
                if 'vrfs' in cfg:
                    summary['vrfs'] = list(cfg['vrfs'].keys()) if isinstance(cfg['vrfs'], dict) else []
                
                if 'bonds' in cfg:
                    summary['bonds'] = list(cfg['bonds'].keys()) if isinstance(cfg['bonds'], dict) else []
                
                if 'vlans' in cfg:
                    summary['vlans'] = list(cfg['vlans'].keys()) if isinstance(cfg['vlans'], dict) else []
                
                if 'evpn' in cfg:
                    summary['evpn'] = True
                
                if summary:
                    device_configs[hostname] = summary
            except Exception:
                pass
    
    if device_configs:
        lines.append("\n--- PER-DEVICE CONFIG SUMMARY (from Ansible host_vars) ---")
        # Group by role for easier comparison
        role_map = {d['hostname']: d['role'] for d in devices.values()}
        by_role = {}
        for hostname, cfg in sorted(device_configs.items()):
            role = role_map.get(hostname, 'unknown')
            by_role.setdefault(role, []).append((hostname, cfg))
        
        for role, devs in sorted(by_role.items()):
            lines.append(f"\n[{role}] ({len(devs)} devices)")
            for hostname, cfg in devs:
                parts = [f"  {hostname}:"]
                if 'asn' in cfg: parts.append(f"ASN={cfg['asn']}")
                if 'router_id' in cfg: parts.append(f"RID={cfg['router_id']}")
                if 'bgp_neighbors' in cfg: parts.append(f"BGP_peers={cfg['bgp_neighbors']}")
                if 'mtus' in cfg: parts.append(f"MTUs={cfg['mtus']}")
                if 'vrfs' in cfg: parts.append(f"VRFs={cfg['vrfs']}")
                if 'bonds' in cfg: parts.append(f"bonds={cfg['bonds']}")
                if 'vlans' in cfg: parts.append(f"vlans={len(cfg['vlans'])} VLANs")
                if 'evpn' in cfg: parts.append("EVPN=yes")
                lines.append(' '.join(parts))
    
    # 3. Pending config changes (from fabric-scan-cache)
    try:
        cache_file = os.path.join(WEB_ROOT, 'fabric-scan-cache.json')
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                cache = json.load(f)
            pending = cache.get('pendingDevices', [])
            if pending:
                lines.append(f"\n--- PENDING CONFIG CHANGES (Ansible diff) ---")
                lines.append(f"{len(pending)} devices have uncommitted changes: {', '.join(pending[:20])}")
    except Exception:
        pass
    
    return "CONFIG CONSISTENCY DATA:\n" + '\n'.join(lines) if lines else "CONFIG DATA: No Ansible config files found."


def build_device_list(devices, device_health):
    """Build token-optimized device list: full detail for problems, summary for healthy.
    This saves ~80% tokens for large fabrics while preserving all actionable info."""
    
    problems = []   # devices with issues — full detail
    healthy_by_role = {}  # role → count of healthy devices
    
    for ip, dev in sorted(devices.items(), key=lambda x: x[1]['hostname']):
        h = device_health.get(dev['hostname'], {})
        status = h.get('status', 'unknown')
        uptime = h.get('uptime', '?')
        release = h.get('release', '?')
        role = dev['role']
        
        # Determine if device has issues
        has_problem = False
        issue_tags = []
        
        # Not responding
        if status != 'ok':
            has_problem = True
            issue_tags.append(f"STATUS:{status}")
        
        # Very short uptime (recent reboot) — under 1 hour
        if uptime and uptime != '?' and ('min' in str(uptime) or uptime.startswith('0:')):
            has_problem = True
            issue_tags.append(f"RECENT_REBOOT:uptime={uptime}")
        
        if has_problem:
            tags = ' '.join(issue_tags)
            problems.append(f"  {dev['hostname']} ({ip}) role={role} {tags} release={release} uptime={uptime}")
        else:
            healthy_by_role[role] = healthy_by_role.get(role, 0) + 1
    
    # Check BGP issues
    try:
        bgp_file = os.path.join(LLDPQ_DIR, 'monitor-results', 'bgp_history.json')
        if os.path.exists(bgp_file):
            with open(bgp_file, 'r') as f:
                bgp = json.load(f)
            for device_name, neighbors in bgp.items():
                if isinstance(neighbors, dict):
                    down_count = sum(1 for n in neighbors.values() if isinstance(n, dict) and n.get('state', '').lower() != 'established')
                    if down_count > 0:
                        # Find this device in our list
                        dev_entry = next((f"  {d['hostname']} ({ip})" for ip, d in devices.items() if d['hostname'] == device_name), None)
                        if dev_entry:
                            bgp_line = f"{dev_entry} BGP_DOWN:{down_count}_sessions"
                            # Add if not already in problems
                            if not any(device_name in p for p in problems):
                                h = device_health.get(device_name, {})
                                ip_addr = next((ip for ip, d in devices.items() if d['hostname'] == device_name), '?')
                                role = next((d['role'] for d in devices.values() if d['hostname'] == device_name), '?')
                                problems.append(f"  {device_name} ({ip_addr}) role={role} BGP_DOWN:{down_count}_sessions")
                            else:
                                # Append BGP info to existing problem line
                                for i, p in enumerate(problems):
                                    if device_name in p:
                                        problems[i] += f" BGP_DOWN:{down_count}_sessions"
                                        break
    except Exception:
        pass
    
    # Build output
    lines = []
    total = len(devices)
    healthy_total = total - len(problems)
    
    if problems:
        lines.append(f"PROBLEM DEVICES ({len(problems)}):")
        lines.extend(problems)
    
    healthy_summary = ', '.join(f"{count} {role}" for role, count in sorted(healthy_by_role.items(), key=lambda x: -x[1]))
    lines.append(f"\nHEALTHY: {healthy_total}/{total} devices ({healthy_summary})")
    lines.append("(Ask about any specific device for full details)")
    
    return '\n'.join(lines)


# ======================== SYSTEM PROMPTS ========================
# Two tiers: COMPACT for small/local models, FULL for cloud/large models

# Small models (ollama, tinyllama, llama3.2, etc.) — keep under 500 tokens
SYSTEM_PROMPT_COMPACT = """You are LLDPq AI, a Cumulus Linux / NVIDIA network expert.
You have access to LIVE monitoring data from a real data center fabric. The data below is from actual devices — use it to answer questions.

IMPORTANT RULES:
- ONLY use the data provided below. Do NOT make up device names, IPs, or statistics.
- Reference actual hostnames and IPs from the data.
- Be concise, use bullet points.
- Suggest NVUE diagnostic commands: nv show router bgp neighbor, nv show interface, nv show interface --view=lldp
- Rate issues as CRITICAL, WARNING, or INFO.
- BGP state "Established" = healthy. Any other state = problem.
- Device status "ok" = healthy. Missing or other = problem.

=== LIVE FABRIC DATA ===

{fabric_summary}

{device_list}

{extra_context}

=== END OF DATA ===

Answer the user's question using ONLY the data above."""

# Large models (Claude, GPT-4o, Gemini Pro, etc.) — full reference + playbooks
SYSTEM_PROMPT_FULL = """You are LLDPq AI, a Cumulus Linux / NVIDIA network expert embedded in a fabric monitoring system.
You have access to LIVE monitoring data from a real data center fabric. ALL data below is from actual devices — treat it as ground truth.

# RESPONSE RULES
- ANSWER THE QUESTION FIRST, directly, from the collected data above (configs, fabric
  tables, OPTICAL DOM, BER/errors, transceiver, hardware, flaps, BGP, logs). This snapshot
  is AUTHORITATIVE for CURRENT state — if it answers the question, lead with the answer
  confidently (e.g. "No optic is degrading — all monitored ports excellent: ber=0, margin
  ~15 dB"). Do NOT open with "I can't answer" or demand telemetry.
- Telemetry (Prometheus) / live tools are needed ONLY for TIME-SERIES (rate over time,
  "last N minutes") or for devices/ports NOT covered by the collected data. Mention them
  only as a brief OPTIONAL next step at the END — never as a prerequisite, and never frame
  a missing time-series as a failure when you already have the current snapshot.
- Don't run live tools / fan-outs to fetch data the collected snapshot already contains.
  Use a live tool only for genuinely missing data, and don't flail through wrong command
  syntaxes — at most a couple of attempts.
- ONLY use real data; NEVER invent device names, IPs, or statistics. Reference ACTUAL
  hostnames, IPs, and ports.
- Be concise. Use bullet points and headers.
- Rate issues: CRITICAL / WARNING / INFO. Prioritize by impact (device down > BGP down > link flap > cosmetic).
- When suggesting commands, use NVUE (nv show/set) as primary, Linux commands as secondary.
- If PART of the question needs data you lack, answer the part you CAN first, then note the
  gap in one line — don't lead with limitations.

# DATA SCHEMA REFERENCE

## device-cache.json (per device)
Fields: hostname, ip, mac (mgmt), serial, model (e.g. "SN5600"), release (Cumulus version), uptime, status, last_seen.
- status "ok" = responding. Anything else = problem.
- Very short uptime (< 1 hour) = device recently rebooted — investigate why.

## fabric-tables/hostname.json (per device, updated every minute)
- arp[]: {{ip, mac, interface, vrf}} — interface="eth0" = mgmt plane.
- mac[]: {{mac, interface, vlan, type}} — type="dynamic" = learned, "static" = configured.
- lldp[]: {{local_port, neighbor, neighbor_port}} — THIS IS the physical topology. swp1→spine-01(swp5) = physical cable.
- routes[]: {{prefix, nexthop, interface, vrf, protocol}} — protocol="bgp" = learned via BGP.
- bonds[]: {{name, members[], mode, status}} — fewer members than expected = partial failure.
- vtep[]: {{vni, local_ip, remote_ip}} — VXLAN tunnel endpoints.

## bgp_history.json
Format: {{hostname: {{neighbor_ip: {{state, prefixes, uptime}}}}}}
- state="Established" = healthy. Idle/Connect/Active/OpenSent/OpenConfirm = DOWN.
- prefixes=0 with Established = session up but no routes exchanged (policy issue).
- Fewer sessions than peers of same role = missing connections.

## lldp_results.ini
Format: [hostname] port = neighbor(port) Status
- Pass = expected match. Fail = wrong cabling. No-Info = port down or no LLDP.
- Many No-Info on one device = device isolated or ports admin-down.

## discovery-cache.json
- device_type: "provisioned" (SSH key OK), "not_provisioned" (no SSH key), "other" (not Cumulus), "unreachable".
- mac_status: "match", "mismatch" (hardware swap?), "no_binding" (not in inventory).

## log_summary.json
- critical > 0 = URGENT. error > 0 = important. warning = often transient.

## TRANSCEIVER INVENTORY (per device/port, when present)
Optic/cable inventory: vendor, part_number (model), serial, fw (firmware), fw_status.
- Mixed fw across the same optic model = firmware should be aligned. Watch fw_status.

## OPTICAL DOM (per host:port, when present)
rx_dBm / tx_dBm (light levels), temp_C, voltage, bias_mA, link margin, health.
- Very low rx (near/below the optic's floor) = dirty/failing fiber or weak far-end Tx.
- health WARN/CRITICAL and low margin = pre-failure; correlate with flaps and BER.

## BER / INTERFACE ERRORS (per host:port, when present)
ber (frame BER), grade, rxErr/txErr, totalPkt, dErr (delta errors since baseline).
- Rising dErr / poor grade = bad optic/cable/connector. Cross-check OPTICAL + flap data.

## HARDWARE (per device, when present)
Raw sensors/thermal/PSU/fan/memory/load text. High temp, failed PSU/fan, or high mem/load = hardware risk.

## Live telemetry (Prometheus, only when telemetry is enabled)
Query cumulus_nvswitch_* metrics with the [PROMQL: <expr>] tool for rate / top-N over
time (in/out discards, errors, AR congestion, rx-buffer, FEC corrections, traffic, flaps).

# NVUE COMMAND REFERENCE

Diagnostic:
- nv show system — hostname, version, uptime, memory
- nv show interface — all interfaces with status, speed, MTU
- nv show interface swpN — specific port details
- nv show interface swpN link state — up/down + carrier transitions (flaps)
- nv show router bgp neighbor — all BGP neighbors with state + prefixes
- nv show router bgp neighbor IP — specific BGP neighbor detail
- nv show vrf — all VRFs
- nv show evpn vni — EVPN VNI table
- nv show bridge domain br_default mac-table — MAC table
- nv show interface --view=lldp — LLDP neighbor table

Config:
- nv set interface swpN link state up/down
- nv set router bgp neighbor IP ...
- nv config apply -y — apply changes
- nv config save — persist across reboot

Linux:
- ip neigh show — ARP table
- ip route show vrf NAME — routes in VRF
- bridge fdb show — MAC/FDB table

# TROUBLESHOOTING PLAYBOOKS

## Device unreachable:
1. Check ping. 2. Check LLDP from neighbors. 3. If LLDP shows it = mgmt issue. No LLDP = physical/power. 4. Check last_seen.

## BGP down:
1. Check state (Idle=unreachable, Active=trying). 2. Check LLDP link. 3. Check flaps. 4. If link up but BGP down = config mismatch. 5. Run: nv show router bgp neighbor IP

## Link flap:
1. Check flap count. >10/hour = bad optic/cable. 2. Check far-end. 3. Run: nv show interface PORT link state + nv show interface PORT pluggable

## Config consistency:
1. Same-role devices should have same ASN, MTU (9216), VRFs, VLAN count, BGP peer count. Differences = misconfiguration.
2. Check pending Ansible changes for config drift.

## MAC mismatch:
Hardware replaced. Update MAC in Inventory → Save → Restart DHCP.

=== LIVE FABRIC DATA ===

{fabric_summary}

{device_list}

{extra_context}

=== END OF DATA ===

Answer the user's question using ONLY the data above."""

# Auto-select prompt based on provider
SMALL_MODEL_PROVIDERS = ('ollama',)

def get_system_prompt():
    if AI_PROVIDER in SMALL_MODEL_PROVIDERS:
        return SYSTEM_PROMPT_COMPACT
    return SYSTEM_PROMPT_FULL


# ======================== LLM PROXY ========================

def call_ollama_stream(messages):
    """Call Ollama API with streaming."""
    import urllib.request
    url = f"{OLLAMA_URL}/api/chat"
    payload = json.dumps({
        "model": AI_MODEL,
        "messages": messages,
        "stream": True
    }).encode()
    
    req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
    try:
        resp = urllib.request.urlopen(req, timeout=120)
        for line in resp:
            try:
                chunk = json.loads(line.decode())
                content = chunk.get('message', {}).get('content', '')
                if content:
                    sse_event({"content": content})
                if chunk.get('done'):
                    break
            except json.JSONDecodeError:
                continue
    except Exception as e:
        sse_event({"error": str(e)}, event="error")


def call_openai_stream(messages):
    """Call OpenAI-compatible API with streaming (works for OpenAI, Claude via proxy, etc.)."""
    import urllib.request
    url = f"{AI_API_URL}/chat/completions"
    payload = json.dumps({
        "model": AI_MODEL,
        "messages": messages,
        "stream": True
    }).encode()
    
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {AI_API_KEY}'
    }
    
    req = urllib.request.Request(url, data=payload, headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=120)
        for line in resp:
            line = line.decode().strip()
            if line.startswith('data: '):
                data_str = line[6:]
                if data_str == '[DONE]':
                    break
                try:
                    chunk = json.loads(data_str)
                    delta = chunk.get('choices', [{}])[0].get('delta', {})
                    content = delta.get('content', '')
                    if content:
                        sse_event({"content": content})
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        sse_event({"error": str(e)}, event="error")


def call_claude_stream(messages):
    """Call Anthropic Claude API with streaming."""
    import urllib.request
    url = f"{AI_API_URL}/messages" if '/messages' not in AI_API_URL else AI_API_URL
    
    # Convert from OpenAI message format to Claude format
    system_msg = ''
    claude_messages = []
    for m in messages:
        if m['role'] == 'system':
            system_msg = m['content']
        else:
            claude_messages.append({"role": m['role'], "content": m['content']})
    
    payload = json.dumps({
        "model": AI_MODEL,
        "max_tokens": 4096,
        "system": system_msg,
        "messages": claude_messages,
        "stream": True
    }).encode()
    
    headers = {
        'Content-Type': 'application/json',
        'x-api-key': AI_API_KEY,
        'anthropic-version': '2023-06-01'
    }
    
    req = urllib.request.Request(url, data=payload, headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=120)
        for line in resp:
            line = line.decode().strip()
            if line.startswith('data: '):
                try:
                    chunk = json.loads(line[6:])
                    if chunk.get('type') == 'content_block_delta':
                        content = chunk.get('delta', {}).get('text', '')
                        if content:
                            sse_event({"content": content})
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        sse_event({"error": str(e)}, event="error")


def call_llm_stream(messages):
    """Route to the appropriate LLM provider."""
    if AI_PROVIDER == 'ollama':
        call_ollama_stream(messages)
    elif AI_PROVIDER == 'claude':
        call_claude_stream(messages)
    else:  # openai or custom
        call_openai_stream(messages)


def call_llm_sync(messages):
    """Synchronous LLM call (for analysis). Returns full response text."""
    import urllib.request
    
    if AI_PROVIDER == 'ollama':
        url = f"{OLLAMA_URL}/api/chat"
        payload = json.dumps({"model": AI_MODEL, "messages": messages, "stream": False}).encode()
        headers = {'Content-Type': 'application/json'}
    elif AI_PROVIDER == 'claude':
        url = f"{AI_API_URL}/messages" if '/messages' not in AI_API_URL else AI_API_URL
        system_msg = ''
        claude_msgs = []
        for m in messages:
            if m['role'] == 'system':
                system_msg = m['content']
            else:
                claude_msgs.append({"role": m['role'], "content": m['content']})
        payload = json.dumps({"model": AI_MODEL, "max_tokens": 4096, "system": system_msg, "messages": claude_msgs}).encode()
        headers = {'Content-Type': 'application/json', 'x-api-key': AI_API_KEY, 'anthropic-version': '2023-06-01'}
    elif AI_PROVIDER == 'gemini':
        # Google Gemini API
        model = AI_MODEL or 'gemini-2.0-flash'
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={AI_API_KEY}"
        # Convert messages to Gemini format
        gemini_contents = []
        system_text = ''
        for m in messages:
            if m['role'] == 'system':
                system_text = m['content']
            elif m['role'] == 'user':
                gemini_contents.append({"role": "user", "parts": [{"text": m['content']}]})
            elif m['role'] == 'assistant':
                gemini_contents.append({"role": "model", "parts": [{"text": m['content']}]})
        # Prepend system text to first user message
        if system_text and gemini_contents:
            first_text = gemini_contents[0]['parts'][0]['text']
            gemini_contents[0]['parts'][0]['text'] = f"[System instruction: {system_text}]\n\n{first_text}"
        payload = json.dumps({"contents": gemini_contents}).encode()
        headers = {'Content-Type': 'application/json'}
    else:
        url = f"{AI_API_URL}/chat/completions"
        payload = json.dumps({"model": AI_MODEL, "messages": messages}).encode()
        headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {AI_API_KEY}'}
    
    req = urllib.request.Request(url, data=payload, headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=500)
        result = json.loads(resp.read().decode())
        if AI_PROVIDER == 'ollama':
            return result.get('message', {}).get('content', '')
        elif AI_PROVIDER == 'claude':
            return result.get('content', [{}])[0].get('text', '')
        elif AI_PROVIDER == 'gemini':
            candidates = result.get('candidates', [])
            if candidates:
                parts = candidates[0].get('content', {}).get('parts', [])
                return parts[0].get('text', '') if parts else ''
            return result.get('error', {}).get('message', 'No response from Gemini')
        else:
            return result.get('choices', [{}])[0].get('message', {}).get('content', '')
    except Exception as e:
        return f"Error: {e}"


# ======================== LIVE DEVICE TOOL (read-only) ========================

TOOL_INSTRUCTIONS = """
=== LIVE DEVICE TOOL (read-only) ===
When the static fabric data above is not enough, you may pull LIVE read-only data
from a device by writing a tool call on its own line, exactly:
[RUN: <device> <command>]
  - <device> = a hostname from the fabric (e.g. tan-leaf-01).
  - <command> = a READ-ONLY show/diagnostic command. Examples:
      nv show interface  |  nv show router bgp  |  nv show evpn vni  |
      nv config show  |  nv config diff  |  sudo vtysh -c 'show bgp summary'  |
      ip route show  |  nv show interface lldp  |  sudo clagctl
    Write/config commands (nv set/unset, nv config apply/replace, reboot, ...) are
    blocked by the backend and will be rejected.
  - Emit at most 3 tool calls per turn. After you receive "TOOL RESULTS", continue;
    request more only if truly needed.
  - When you have enough, give your FINAL answer with NO [RUN: ...] / [RUNALL: ...] lines.
  - Prefer the collected data above; use live tools only when current state is needed.

For a fabric-wide check, fan ONE command out to many devices IN PARALLEL:
[RUNALL: <target> <command>]
  - <target> = "all" (every device) or a role/name substring (e.g. leaf, spine, border).
  - Same read-only command rules as [RUN:]. Use this instead of many [RUN:] lines when
    comparing the same thing across devices (e.g. BGP summary on all leaves).
  - At most one fan-out per turn; results return per device.

For live streaming-telemetry metrics (only when telemetry is enabled), query Prometheus:
[PROMQL: <PromQL expression>]
  - Cumulus telemetry metrics are named cumulus_nvswitch_* (interface in/out errors,
    in/out discards, AR congestion, rx-buffer, drops, traffic, FEC corrections, flaps).
    Example: [PROMQL: topk(10, rate(cumulus_nvswitch_interface_if_in_discards[5m]))]
  - Read-only; ideal for "last N minutes", rate, and top-N questions. If telemetry is
    off you'll get an error — fall back to the collected data above.

For a metric TREND over time (only when telemetry is enabled):
[PROMQLRANGE: <PromQL> | <range> | <step>]
  - range/step like 15m, 1h, 24h / 30s, 60s. Returns first/min/max/last per series so
    you can state whether something is rising/falling.
    Example: [PROMQLRANGE: rate(cumulus_nvswitch_interface_if_in_discards[2m]) | 1h | 60s]

To check reachability / trace the path between two endpoints (graph-based, read-only):
[PATH: <source> <dest_ip>]
  - <source> = a device hostname OR a source IP; <dest_ip> = the destination IP.
  - Returns the hop-by-hop path (or where it breaks). Use for "how does A reach B",
    blackhole, or asymmetric-routing questions.

=== REMEDIATION SUGGESTIONS ===
When you recommend a command the operator should RUN to fix something, put it on its own
line exactly as:
[FIX: <device-or-group> <command>]
  - This is a SUGGESTION rendered as a one-click button — you do NOT execute it.
  - Use a real device/group name and a concrete command (e.g.
    [FIX: tan-leaf-01 nv set interface swp5 link state up] then nv config apply).
  - Only suggest safe, intentional changes; never destructive commands.

=== FOLLOW-UPS & LIVE CONSOLE ===
End your answer with up to 3 helpful next questions, each on its own line:
[NEXT: <a concise, specific follow-up question>]
  - Rendered as one-click chips. Tailor them to your answer (not generic).

If hands-on interactive access would help (multi-step debugging, editing config, or a
TUI like vtysh / top), suggest opening a live terminal:
[CONSOLE: <device>]
  - <device> = a real fabric hostname. Rendered as an "Open live Console" button.
"""


def run_device_tool(device, command, cookie):
    """Run ONE read-only device command by invoking fabric-api.sh's run-device-command
    as a subprocess. This reuses its exact read-only whitelist, admin auth (via the
    forwarded session cookie) and ssh exec — nothing is duplicated. Never raises."""
    import subprocess
    try:
        body = json.dumps({'device': device, 'command': command})
        env = dict(os.environ)
        env['REQUEST_METHOD'] = 'POST'
        env['QUERY_STRING'] = 'action=run-device-command'
        env['CONTENT_TYPE'] = 'application/json'
        env['CONTENT_LENGTH'] = str(len(body.encode('utf-8')))
        if cookie:
            env['HTTP_COOKIE'] = cookie
        proc = subprocess.run(
            ['bash', os.path.join(WEB_ROOT, 'fabric-api.sh')],
            input=body, env=env, capture_output=True, text=True, timeout=60
        )
        raw = proc.stdout or ''
        for sep in ('\r\n\r\n', '\n\n'):
            if sep in raw:
                raw = raw.split(sep, 1)[1]
                break
        d = json.loads(raw.strip())
        if d.get('success'):
            return True, (d.get('output') or '(no output)')
        return False, (d.get('error') or 'command rejected')
    except subprocess.TimeoutExpired:
        return False, 'tool timed out'
    except Exception as e:
        return False, f'tool error: {e}'


def run_dispatch(target, command, devices, cookie, max_devices=60, pool=8, per_out=1200):
    """Phase 3: run ONE read-only command on many devices in PARALLEL (fan-out).
    target = 'all'/'*' or a role/hostname substring (e.g. 'leaf', 'spine', 'border').
    Returns (hostnames, {hostname: (ok, output)}). Reuses run_device_tool per device."""
    from concurrent.futures import ThreadPoolExecutor
    t = (target or '').strip().lstrip('@').lower()
    targets = []
    for ip, dev in devices.items():
        hn = dev.get('hostname', '')
        role = (dev.get('role', '') or '').lower()
        if not hn:
            continue
        if t in ('all', '*', '') or t in role or t in hn.lower():
            targets.append(hn)
    targets = sorted(set(targets))[:max_devices]
    results = {}
    if not targets:
        return targets, results

    def _one(h):
        ok, out = run_device_tool(h, command, cookie)
        return h, ok, (out or '')[:per_out]

    try:
        with ThreadPoolExecutor(max_workers=min(pool, len(targets))) as ex:
            for h, ok, out in ex.map(_one, targets):
                results[h] = (ok, out)
    except Exception as e:
        for h in targets:
            results.setdefault(h, (False, f'dispatch error: {e}'))
    return targets, results


def run_promql(query, cookie, max_rows=60):
    """Live streaming-telemetry query via fabric-api.sh prometheus-query (read-only).
    Returns (ok, text). Degrades gracefully when telemetry/Prometheus is unavailable."""
    import subprocess
    try:
        body = json.dumps({'query': query})
        env = dict(os.environ)
        env['REQUEST_METHOD'] = 'POST'
        env['QUERY_STRING'] = 'action=prometheus-query'
        env['CONTENT_TYPE'] = 'application/json'
        env['CONTENT_LENGTH'] = str(len(body.encode('utf-8')))
        if cookie:
            env['HTTP_COOKIE'] = cookie
        proc = subprocess.run(
            ['bash', os.path.join(WEB_ROOT, 'fabric-api.sh')],
            input=body, env=env, capture_output=True, text=True, timeout=30
        )
        raw = proc.stdout or ''
        for sep in ('\r\n\r\n', '\n\n'):
            if sep in raw:
                raw = raw.split(sep, 1)[1]
                break
        d = json.loads(raw.strip())
        if not d.get('success'):
            return False, (d.get('error') or 'query failed')
        res = ((d.get('data') or {}).get('result')) or []
        rows = []
        for r in res[:max_rows]:
            m = r.get('metric', {}) or {}
            host = m.get('net_host_name') or m.get('instance') or ''
            iface = m.get('swp') or m.get('interface') or ''
            val = (r.get('value') or [None, ''])[1]
            rows.append(f"  {host} {iface} = {val}")
        return True, ('\n'.join(rows) if rows else '(no series matched)')
    except subprocess.TimeoutExpired:
        return False, 'promql timed out'
    except Exception as e:
        return False, f'promql error: {e}'


def run_tracepath(src, dst, cookie):
    """Read-only graph-based path discovery via search-api.sh. src may be a device
    hostname or an IP; dst is a destination IP. Returns (ok, compact_json_text)."""
    import subprocess
    import urllib.parse
    try:
        def is_ip(s):
            s = s or ''
            return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s)) or ':' in s
        if is_ip(src) and is_ip(dst):
            qs = ('action=trace-path-ip'
                  f'&source_ip={urllib.parse.quote(src)}'
                  f'&dest_ip={urllib.parse.quote(dst)}&vrf=default')
        else:
            qs = ('action=trace-path'
                  f'&source={urllib.parse.quote(src)}'
                  f'&ip={urllib.parse.quote(dst)}&vrf=default')
        env = dict(os.environ)
        env['REQUEST_METHOD'] = 'GET'
        env['QUERY_STRING'] = qs
        if cookie:
            env['HTTP_COOKIE'] = cookie
        proc = subprocess.run(
            ['bash', os.path.join(WEB_ROOT, 'search-api.sh')],
            env=env, capture_output=True, text=True, timeout=60
        )
        raw = proc.stdout or ''
        for sep in ('\r\n\r\n', '\n\n'):
            if sep in raw:
                raw = raw.split(sep, 1)[1]
                break
        d = json.loads(raw.strip())
        if isinstance(d, dict) and d.get('success') is False and d.get('error'):
            return False, str(d.get('error'))
        return True, json.dumps(d)[:4000]
    except subprocess.TimeoutExpired:
        return False, 'tracepath timed out'
    except Exception as e:
        return False, f'tracepath error: {e}'


def run_promql_range(query, rng, step, cookie, max_series=30):
    """Live telemetry range query via fabric-api.sh prometheus-query-range (read-only).
    Summarizes each series as first/min/max/last + trend arrow over the window."""
    import subprocess
    try:
        body = json.dumps({'query': query, 'range': rng or '15m', 'step': step or '60s'})
        env = dict(os.environ)
        env['REQUEST_METHOD'] = 'POST'
        env['QUERY_STRING'] = 'action=prometheus-query-range'
        env['CONTENT_TYPE'] = 'application/json'
        env['CONTENT_LENGTH'] = str(len(body.encode('utf-8')))
        if cookie:
            env['HTTP_COOKIE'] = cookie
        proc = subprocess.run(
            ['bash', os.path.join(WEB_ROOT, 'fabric-api.sh')],
            input=body, env=env, capture_output=True, text=True, timeout=40
        )
        raw = proc.stdout or ''
        for sep in ('\r\n\r\n', '\n\n'):
            if sep in raw:
                raw = raw.split(sep, 1)[1]
                break
        d = json.loads(raw.strip())
        if not d.get('success'):
            return False, (d.get('error') or 'range query failed')
        res = ((d.get('data') or {}).get('result')) or []
        rows = []
        for r in res[:max_series]:
            m = r.get('metric', {}) or {}
            host = m.get('net_host_name') or m.get('instance') or ''
            iface = m.get('swp') or m.get('interface') or ''
            try:
                vals = [float(v[1]) for v in (r.get('values') or []) if v and v[1] not in ('NaN', None)]
            except Exception:
                vals = []
            if not vals:
                continue
            arrow = '^' if vals[-1] > vals[0] else ('v' if vals[-1] < vals[0] else '=')
            rows.append(f"  {host} {iface}: first={vals[0]:.3g} min={min(vals):.3g} "
                        f"max={max(vals):.3g} last={vals[-1]:.3g} {arrow}")
        return True, ('\n'.join(rows) if rows else '(no series matched)')
    except subprocess.TimeoutExpired:
        return False, 'range query timed out'
    except Exception as e:
        return False, f'range query error: {e}'


# ======================== ACTIONS ========================

SEARCH_INSTRUCTIONS = """
[SEARCH: <query>]
  - Look up CURRENT external info (known Cumulus/SONiC bugs, release notes, CVEs,
    advisories, vendor docs) when the fabric data above is not enough to answer.
  - Use sparingly (max 2 per question). Cite the source URLs returned.
"""

def action_chat():
    """Handle chat message — synchronous response (fcgiwrap doesn't support SSE streaming)."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON")
    
    question = data.get('message', '').strip()
    history = data.get('history', [])  # previous messages for context
    
    if not question:
        error_json("Empty message")

    # Operator teaches a persistent fact: "remember: <fact>" (also hatırla:/unutma:).
    _mem = re.match(r'^\s*(?:remember|remember that|hat[\u0131i]rla|unutma)\s*[:,]?\s+(.+)$',
                    question, re.IGNORECASE | re.DOTALL)
    if _mem:
        fact = _mem.group(1).strip()
        add_learning(fact)
        result_json({"success": True, "response": "Got it — I'll remember that: " + fact,
                     "tools_used": [], "fixes": [], "followups": [], "consoles": [], "learned": fact})
    
    # Build context
    fabric_summary, devices, device_health = build_fabric_summary()
    extra_context = maybe_redact(build_context_for_question(question, devices, device_health))
    device_list = build_device_list(devices, device_health)
    
    system_prompt = get_system_prompt().format(
        fabric_summary=fabric_summary,
        device_list=device_list,
        extra_context=extra_context
    ) + "\n" + TOOL_INSTRUCTIONS
    if SEARCH_ENABLED:
        system_prompt += "\n" + SEARCH_INSTRUCTIONS
    
    # Build messages array
    messages = [{"role": "system", "content": system_prompt}]
    
    # Add conversation history (last 10 messages for context window)
    for msg in history[-10:]:
        messages.append({"role": msg.get('role', 'user'), "content": msg.get('content', '')})
    
    messages.append({"role": "user", "content": question})
    
    # Bounded read-only tool-calling loop. The model may emit [RUN: device command]
    # to pull live data; each call is executed via fabric-api.sh run-device-command
    # (its read-only whitelist + admin auth + ssh exec are reused, not duplicated).
    cookie = os.environ.get('HTTP_COOKIE', '')
    valid_hostnames = {d.get('hostname', '') for d in devices.values() if d.get('hostname')}
    MAX_ROUNDS = 4
    MAX_TOOLS_PER_ROUND = 3
    MAX_TOTAL_TOOLS = 10
    MAX_DISPATCHES = 2            # [RUNALL: ...] parallel fan-outs per question
    DISPATCH_DEVICE_CAP = 120     # total devices across all dispatches
    MAX_PROMQL = 4                # [PROMQL: ...] live telemetry queries per question
    MAX_SEARCH = 2                # [SEARCH: ...] web-research queries per question
    deadline = time.time() + 220  # keep whole request under nginx's 300s read timeout
    total_tools = 0
    dispatches_used = 0
    dispatch_dev_total = 0
    promql_used = 0
    searches_used = 0
    response = ''
    tools_used = []
    
    for _round in range(MAX_ROUNDS):
        response = call_llm_sync(messages)
        runs = re.findall(r'\[RUN:\s*(\S+)\s+([^\]]+)\]', response or '')
        runalls = re.findall(r'\[RUNALL:\s*(\S+)\s+([^\]]+)\]', response or '')
        promqls = re.findall(r'\[PROMQL:\s*(.+)\]', response or '')  # greedy: PromQL may contain ] (e.g. [5m])
        promranges = re.findall(r'\[PROMQLRANGE:\s*(.+)\]', response or '')
        paths = re.findall(r'\[PATH:\s*(\S+)\s+(\S+)\]', response or '')
        searches = re.findall(r'\[SEARCH:\s*(.+?)\]', response or '') if SEARCH_ENABLED else []
        if (not runs and not runalls and not promqls and not promranges and not paths and not searches) or time.time() > deadline:
            break
        results = []
        # Single-device read-only tools
        for dev_name, cmd in runs[:MAX_TOOLS_PER_ROUND]:
            if total_tools >= MAX_TOTAL_TOOLS or time.time() > deadline:
                break
            dev_name = dev_name.strip()
            cmd = cmd.strip()
            if dev_name not in valid_hostnames:
                results.append(f"[{dev_name}] error: unknown device (not in fabric)")
                continue
            ok, out = run_device_tool(dev_name, cmd, cookie)
            total_tools += 1
            tools_used.append({'device': dev_name, 'command': cmd, 'ok': ok})
            results.append(f"[RUN {dev_name}: {cmd}]\n{(out or '')[:6000]}")
        # Parallel multi-device fan-out (Phase 3): at most one dispatch per round
        for tgt, cmd in runalls[:1]:
            if dispatches_used >= MAX_DISPATCHES or dispatch_dev_total >= DISPATCH_DEVICE_CAP or time.time() > deadline:
                break
            tgt = tgt.strip()
            cmd = cmd.strip()
            hosts, dres = run_dispatch(tgt, cmd, devices, cookie,
                                       max_devices=min(60, DISPATCH_DEVICE_CAP - dispatch_dev_total))
            dispatches_used += 1
            dispatch_dev_total += len(hosts)
            tools_used.append({'dispatch': tgt, 'command': cmd, 'devices': len(hosts)})
            lines = [f"[RUNALL {tgt}: {cmd}]  ({len(hosts)} devices, parallel)"]
            for h in hosts:
                ok, out = dres.get(h, (False, ''))
                lines.append(f"--- {h} [{'OK' if ok else 'FAIL'}] ---\n{out}")
            results.append('\n'.join(lines))
        # Live telemetry (PromQL) queries
        for q in promqls[:2]:
            if promql_used >= MAX_PROMQL or time.time() > deadline:
                break
            q = q.strip()
            ok, out = run_promql(q, cookie)
            promql_used += 1
            tools_used.append({'promql': q, 'ok': ok})
            results.append(f"[PROMQL: {q}]\n{out}")
        # Live telemetry trend (PromQL range)
        for spec in promranges[:2]:
            if promql_used >= MAX_PROMQL or time.time() > deadline:
                break
            parts = [p.strip() for p in spec.split('|')]
            q = parts[0] if parts else ''
            rng = parts[1] if len(parts) > 1 else '15m'
            step = parts[2] if len(parts) > 2 else '60s'
            ok, out = run_promql_range(q, rng, step, cookie)
            promql_used += 1
            tools_used.append({'promqlrange': q, 'range': rng, 'ok': ok})
            results.append(f"[PROMQLRANGE: {q} | {rng} | {step}]\n{out}")
        # Path discovery (graph-based tracepath)
        for src, dst in paths[:2]:
            if total_tools >= MAX_TOTAL_TOOLS or time.time() > deadline:
                break
            src, dst = src.strip(), dst.strip()
            ok, out = run_tracepath(src, dst, cookie)
            total_tools += 1
            tools_used.append({'path': f'{src} -> {dst}', 'ok': ok})
            results.append(f"[PATH {src} -> {dst}]\n{out}")
        # Web research (known bugs / release notes / advisories)
        for q in searches[:1]:
            if searches_used >= MAX_SEARCH or time.time() > deadline:
                break
            q = q.strip()
            out = run_search(q)
            searches_used += 1
            tools_used.append({'search': q})
            results.append(f"[SEARCH: {q}]\n{out}")
        messages.append({"role": "assistant", "content": response})
        messages.append({"role": "user", "content":
            "TOOL RESULTS:\n" + maybe_redact("\n\n".join(results)) +
            "\n\nContinue. Request more data only if needed; otherwise give the final answer with no [RUN: ...] / [RUNALL: ...] / [PROMQL: ...] / [PROMQLRANGE: ...] / [PATH: ...] lines."})
    
    # If still requesting tools (hit the round cap), force one final answer.
    if re.search(r'\[(?:RUN(?:ALL)?|PROMQLRANGE|PROMQL|PATH|SEARCH):', response or '') and time.time() < deadline:
        messages.append({"role": "assistant", "content": response})
        messages.append({"role": "user", "content":
            "Stop using tools. Give your final answer now from the results above; do not emit any data-tool lines ([RUN:]/[RUNALL:]/[PROMQL:]/[PROMQLRANGE:]/[PATH:]). You MAY include [FIX: ...], [NEXT: ...] and [CONSOLE: ...] suggestions."})
        response = call_llm_sync(messages)
    
    # Suggested remediation commands (NOT executed) -> returned as one-click buttons.
    fixes = []
    for dev, cmd in re.findall(r'\[FIX:\s*(\S+)\s+(.+?)\]', response or ''):
        fixes.append({'device': dev.strip(), 'command': cmd.strip()})
    # Suggested follow-up questions -> one-click chips.
    followups = [q.strip() for q in re.findall(r'\[NEXT:\s*(.+?)\]', response or '')][:4]
    # Suggested live-console targets -> "Open Console" buttons (validated against the fabric).
    consoles = []
    for dev in re.findall(r'\[CONSOLE:\s*([^\]\s]+)\s*\]', response or ''):
        dev = dev.strip()
        if dev in valid_hostnames and dev not in consoles:
            consoles.append(dev)
    
    # Strip leftover tool-call / suggestion lines from the visible answer (line-based:
    # robust even when a PromQL expression contains ']' like a [5m] range selector).
    final = '\n'.join(
        ln for ln in (response or '').splitlines()
        if not re.search(r'\[(?:RUN(?:ALL)?|PROMQLRANGE|PROMQL|PATH|SEARCH|FIX|NEXT|CONSOLE):', ln)
    ).strip()
    
    result_json({"success": True, "response": final, "tools_used": tools_used,
                 "fixes": fixes, "followups": followups, "consoles": consoles})


def action_get_context():
    """Return the current fabric summary (for UI context indicator)."""
    fabric_summary, devices, device_health = build_fabric_summary()
    device_names = sorted(set(d['hostname'] for d in devices.values() if d['hostname']))
    result_json({
        "success": True,
        "summary": fabric_summary,
        "device_count": len(devices),
        "roles": {role: sum(1 for d in devices.values() if d['role'] == role) for role in set(d['role'] for d in devices.values())},
        "device_names": device_names,
    })


def action_get_config():
    """Return current AI configuration."""
    # Mask API key
    masked_key = ''
    if AI_API_KEY:
        masked_key = AI_API_KEY[:8] + '...' + AI_API_KEY[-4:] if len(AI_API_KEY) > 12 else '***'
    
    result_json({
        "success": True,
        "provider": AI_PROVIDER,
        "model": AI_MODEL,
        "api_url": AI_API_URL,
        "api_key_masked": masked_key,
        "ollama_url": OLLAMA_URL,
        "has_key": bool(AI_API_KEY),
        "proxy_url": AI_PROXY_URL,
        "search_model": AI_SEARCH_MODEL,
        "search_enabled": SEARCH_ENABLED,
    })


def action_save_config():
    """Save AI configuration to lldpq.conf."""
    try:
        data = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON")
    
    import shlex
    import subprocess, fcntl
    conf = '/etc/lldpq.conf'
    
    updates = {}
    if 'provider' in data:
        updates['AI_PROVIDER'] = data['provider']
    if 'model' in data:
        updates['AI_MODEL'] = data['model']
    if 'api_key' in data and data['api_key']:
        updates['AI_API_KEY'] = data['api_key']
    if 'api_url' in data:
        updates['AI_API_URL'] = data['api_url']
    if 'ollama_url' in data:
        updates['OLLAMA_URL'] = data['ollama_url']
    if 'proxy_url' in data:
        updates['AI_PROXY_URL'] = data['proxy_url']
    if 'search_model' in data:
        updates['AI_SEARCH_MODEL'] = data['search_model']
    
    try:
        lock_fd = open(conf + '.lock', 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        try:
            with open(conf, 'r') as f:
                lines = f.readlines()
            for key, value in updates.items():
                rendered = shlex.quote(str(value))
                found = False
                for i, line in enumerate(lines):
                    if line.startswith(f'{key}='):
                        lines[i] = f'{key}={rendered}\n'
                        found = True
                        break
                if not found:
                    lines.append(f'{key}={rendered}\n')
            content = ''.join(lines)
            try:
                with open(conf, 'w') as f:
                    f.write(content)
            except PermissionError:
                subprocess.run(['sudo', '-n', 'tee', conf], input=content, capture_output=True, text=True, timeout=5)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()
    except Exception as e:
        error_json(f"Failed to save config: {e}")
    
    result_json({"success": True, "message": "AI configuration saved"})


def action_test_connection():
    """Test LLM connection."""
    try:
        data = json.loads(POST_DATA) if POST_DATA else {}
    except Exception:
        data = {}
    
    provider = data.get('provider', AI_PROVIDER)
    model = data.get('model', AI_MODEL)
    
    # Set proxy for test if provided
    proxy_url = data.get('proxy_url', '')
    if proxy_url:
        os.environ['http_proxy'] = proxy_url
        os.environ['https_proxy'] = proxy_url
    elif AI_PROXY_URL:
        os.environ['http_proxy'] = AI_PROXY_URL
        os.environ['https_proxy'] = AI_PROXY_URL
    
    messages = [
        {"role": "system", "content": "You are a helpful assistant. Reply with exactly: OK"},
        {"role": "user", "content": "Test connection. Reply with: OK"}
    ]
    
    start = time.time()
    try:
        if provider == 'ollama':
            import urllib.request
            url = data.get('ollama_url', OLLAMA_URL) + '/api/chat'
            payload = json.dumps({"model": model, "messages": messages, "stream": False}).encode()
            req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
            resp = urllib.request.urlopen(req, timeout=30)
            result = json.loads(resp.read().decode())
            reply = result.get('message', {}).get('content', '')
            elapsed = round(time.time() - start, 1)
            result_json({"success": True, "reply": reply.strip(), "elapsed": elapsed, "model": model})
        elif provider == 'gemini':
            import urllib.request
            api_key = data.get('api_key', AI_API_KEY)
            # Set proxy if provided in test payload
            proxy_url = data.get('proxy_url', '')
            if proxy_url:
                os.environ['http_proxy'] = proxy_url
                os.environ['https_proxy'] = proxy_url
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
            payload = json.dumps({"contents": [{"role": "user", "parts": [{"text": "Test connection. Reply with exactly: OK"}]}]}).encode()
            headers = {'Content-Type': 'application/json'}
            req = urllib.request.Request(url, data=payload, headers=headers)
            resp = urllib.request.urlopen(req, timeout=30)
            result = json.loads(resp.read().decode())
            candidates = result.get('candidates', [])
            reply = candidates[0]['content']['parts'][0]['text'] if candidates else 'No response'
        else:
            # OpenAI-compatible
            import urllib.request
            api_url = data.get('api_url', AI_API_URL)
            api_key = data.get('api_key', AI_API_KEY)
            if provider == 'claude':
                url = f"{api_url}/messages" if '/messages' not in api_url else api_url
                payload = json.dumps({"model": model, "max_tokens": 100, "messages": [{"role": "user", "content": "Test. Reply: OK"}]}).encode()
                headers = {'Content-Type': 'application/json', 'x-api-key': api_key, 'anthropic-version': '2023-06-01'}
            else:
                url = f"{api_url}/chat/completions"
                payload = json.dumps({"model": model, "messages": messages}).encode()
                headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {api_key}'}
            req = urllib.request.Request(url, data=payload, headers=headers)
            resp = urllib.request.urlopen(req, timeout=30)
            result = json.loads(resp.read().decode())
            if provider == 'claude':
                reply = result.get('content', [{}])[0].get('text', '')
            else:
                reply = result.get('choices', [{}])[0].get('message', {}).get('content', '')
            elapsed = round(time.time() - start, 1)
            result_json({"success": True, "reply": reply.strip(), "elapsed": elapsed, "model": model})
    except Exception as e:
        elapsed = round(time.time() - start, 1)
        error_msg = str(e)
        if 'urlopen error' in error_msg:
            error_msg = f"Connection failed: {error_msg}. Is the service running?"
        result_json({"success": False, "error": error_msg, "elapsed": elapsed})


def action_list_models():
    """List available models from Ollama."""
    import urllib.request
    try:
        url = f"{OLLAMA_URL}/api/tags"
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())
        models = [m.get('name', '') for m in data.get('models', [])]
        result_json({"success": True, "models": models})
    except Exception as e:
        result_json({"success": True, "models": [], "error": str(e)})


def action_analyze():
    """Run autonomous fabric health analysis (with change detection vs the previous run)."""
    fabric_summary, devices, device_health = build_fabric_summary()
    device_list = build_device_list(devices, device_health)

    # Change detection: diff this run's per-device status against the previous snapshot.
    snap_file = os.path.join(WEB_ROOT, 'ai-analysis-snapshot.json')
    cur_snap = _health_snapshot(devices, device_health)
    prev_snap = (_load_json_file(snap_file) or {}).get('statuses', {})
    changes = _diff_snapshots(prev_snap, cur_snap)
    changes_text = ("CHANGES SINCE LAST RUN:\n" + "\n".join("  - " + c for c in changes)) \
        if changes else "CHANGES SINCE LAST RUN: none — device status unchanged."

    prompt = f"""Analyze this network fabric health data and report any issues, anomalies, or concerns.
Be specific: mention device names, IPs, and exact metrics.
Categorize findings as: CRITICAL, WARNING, or INFO.
LEAD your report with what CHANGED since the last run (section below) when anything changed;
then cover current issues. If everything is healthy and nothing changed, say so briefly.

{changes_text}

{fabric_summary}

DEVICE LIST:
{device_list}"""
    
    messages = [
        {"role": "system", "content": "You are a network health analyzer. Analyze the data and report findings categorized by severity. Be concise and specific."},
        {"role": "user", "content": prompt}
    ]
    
    response = call_llm_sync(messages)
    
    analysis = {
        "timestamp": time.time(),
        "analysis": response,
        "device_count": len(devices),
        "provider": AI_PROVIDER,
        "model": AI_MODEL,
        "changes": changes,
    }
    
    # Save analysis
    try:
        with open(ANALYSIS_FILE, 'w') as f:
            json.dump(analysis, f, indent=2)
    except PermissionError:
        import subprocess
        subprocess.run(['sudo', '-n', 'tee', ANALYSIS_FILE],
                      input=json.dumps(analysis, indent=2), capture_output=True, text=True, timeout=10)
        subprocess.run(['sudo', '-n', 'chown', f'{LLDPQ_USER}:www-data', ANALYSIS_FILE], capture_output=True, timeout=5)
        subprocess.run(['sudo', '-n', 'chmod', '664', ANALYSIS_FILE], capture_output=True, timeout=5)
    
    # Persist this run's snapshot for next-run change detection.
    try:
        _save_json_web(snap_file, {"timestamp": time.time(), "statuses": cur_snap})
    except Exception:
        pass

    result_json({"success": True, "analysis": response, "timestamp": analysis['timestamp'], "changes": changes})


def action_get_analysis():
    """Get the latest autonomous analysis."""
    if not os.path.exists(ANALYSIS_FILE):
        result_json({"success": True, "analysis": "", "timestamp": 0, "stale": True})
    try:
        with open(ANALYSIS_FILE, 'r') as f:
            data = json.load(f)
        age = time.time() - data.get('timestamp', 0)
        data['success'] = True
        data['stale'] = age > 3600
        data['age_seconds'] = int(age)
        result_json(data)
    except Exception:
        result_json({"success": True, "analysis": "", "timestamp": 0, "stale": True})


# ======================== ROUTER ========================

if ACTION == 'chat':
    action_chat()
elif ACTION == 'get-context':
    action_get_context()
elif ACTION == 'get-config':
    action_get_config()
elif ACTION == 'save-config':
    action_save_config()
elif ACTION == 'test-connection':
    action_test_connection()
elif ACTION == 'list-models':
    action_list_models()
elif ACTION == 'analyze':
    action_analyze()
elif ACTION == 'get-analysis':
    action_get_analysis()
elif ACTION == 'get-log-messages':
    try:
        log_file = os.path.join(LLDPQ_DIR, 'monitor-results', 'log_summary.json')
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                data = json.load(f)
            result_json({"success": True, "messages": data.get('recent_messages', {}), "totals": data.get('totals', {})})
        else:
            result_json({"success": True, "messages": {}, "totals": {}})
    except Exception as e:
        error_json(str(e))
elif ACTION == 'get-learnings':
    result_json({"success": True, "learnings": load_learnings(), "search_enabled": SEARCH_ENABLED})
elif ACTION == 'save-learnings':
    try:
        _d = json.loads(POST_DATA)
    except Exception:
        error_json("Invalid JSON")
    _items = save_learnings(_d.get('learnings', []))
    result_json({"success": True, "count": len(_items)})
else:
    error_json(f"Unknown action: {ACTION}")

PYTHON_SCRIPT
