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

# Set HTTP proxy if configured (allows airgapped servers to reach cloud APIs via SSH tunnel)
if AI_PROXY_URL:
    os.environ['http_proxy'] = AI_PROXY_URL
    os.environ['https_proxy'] = AI_PROXY_URL

ANALYSIS_FILE = os.path.join(WEB_ROOT, 'ai-analysis.json')

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


def build_context_for_question(question, devices, device_health):
    """Build targeted context based on the question content."""
    extra_context = []
    q_lower = question.lower()
    
    # Detect specific device mentions
    for ip, dev in devices.items():
        if dev['hostname'].lower() in q_lower or ip in q_lower:
            extra_context.append(build_device_detail(dev['hostname'], devices, device_health))
    
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
- ONLY use the data provided below. NEVER invent device names, IPs, or statistics.
- Always reference ACTUAL hostnames, IPs, and ports from the data.
- Be concise. Use bullet points and headers.
- Rate issues: CRITICAL / WARNING / INFO. Prioritize by impact (device down > BGP down > link flap > cosmetic).
- When suggesting commands, use NVUE (nv show/set) as primary, Linux commands as secondary.
- If data is insufficient, say EXACTLY what additional data you need.

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


# ======================== ACTIONS ========================

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
    
    # Build context
    fabric_summary, devices, device_health = build_fabric_summary()
    extra_context = build_context_for_question(question, devices, device_health)
    device_list = build_device_list(devices, device_health)
    
    system_prompt = get_system_prompt().format(
        fabric_summary=fabric_summary,
        device_list=device_list,
        extra_context=extra_context
    )
    
    # Build messages array
    messages = [{"role": "system", "content": system_prompt}]
    
    # Add conversation history (last 10 messages for context window)
    for msg in history[-10:]:
        messages.append({"role": msg.get('role', 'user'), "content": msg.get('content', '')})
    
    messages.append({"role": "user", "content": question})
    
    # Synchronous LLM call
    response = call_llm_sync(messages)
    
    result_json({"success": True, "response": response})


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
    """Run autonomous fabric health analysis."""
    fabric_summary, devices, device_health = build_fabric_summary()
    device_list = build_device_list(devices, device_health)
    
    prompt = f"""Analyze this network fabric health data and report any issues, anomalies, or concerns.
Be specific: mention device names, IPs, and exact metrics.
Categorize findings as: CRITICAL, WARNING, or INFO.
If everything looks healthy, say so briefly.

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
    
    result_json({"success": True, "analysis": response, "timestamp": analysis['timestamp']})


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
else:
    error_json(f"Unknown action: {ACTION}")

PYTHON_SCRIPT
