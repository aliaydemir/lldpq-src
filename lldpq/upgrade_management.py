"""Conservative static IPv6 recovery checks for an ONIE image replacement.

YAML is parsed on the collector, where it is already a dependency. The remote
probe uses only Python's standard library and iproute2. This establishes saved
address/return-route evidence, not that a particular image will boot correctly.
"""
import base64
import hashlib
import ipaddress
import json
import shlex


# Executed over SSH, including immediately before dispatch with an expected
# snapshot. Never installs dependencies or changes interface configuration.
REMOTE_PROBE = r'''
import base64, hashlib, ipaddress, json, os, re, subprocess, sys, tempfile

def read_json(argv):
    result = subprocess.run(argv, check=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True, timeout=5)
    return json.loads(result.stdout)

def probe(connection):
    fields = connection.split()
    if len(fields) != 4:
        raise ValueError('SSH_CONNECTION is unavailable; cannot verify management transport')
    client = ipaddress.ip_address(fields[0].split('%')[0])
    server = ipaddress.ip_address(fields[2].split('%')[0])
    snapshot = {'family': server.version, 'server': str(server), 'client': str(client)}
    if server.version == 4:
        return snapshot
    matches = []
    for link in read_json(['ip', '-j', '-6', 'address', 'show']):
        for address in link.get('addr_info', []):
            if address.get('family') == 'inet6' and ipaddress.ip_address(address['local']) == server:
                if any(address.get(flag) for flag in ('temporary', 'tentative', 'dadfailed', 'deprecated', 'dynamic')):
                    raise ValueError('Management IPv6 is temporary, dynamic, tentative or deprecated')
                matches.append((link, address))
    if len(matches) != 1:
        raise ValueError('Management IPv6 must identify exactly one local interface')
    link, address = matches[0]
    interface = link['ifname']
    details = read_json(['ip', '-j', '-d', 'link', 'show', 'dev', interface])[0]
    vrf = details.get('master', '') or ''
    if vrf:
        master = read_json(['ip', '-j', '-d', 'link', 'show', 'dev', vrf])[0]
        if master.get('linkinfo', {}).get('info_kind') != 'vrf':
            raise ValueError('Management interface has a non-VRF master; recovery cannot be established')
    argv = ['ip', '-j', '-6', 'route', 'get', str(client), 'from', str(server)]
    if vrf:
        argv += ['vrf', vrf]
    if server.is_link_local:
        argv += ['oif', interface]
    routes = read_json(argv)
    if len(routes) != 1 or routes[0].get('type', 'unicast') != 'unicast':
        raise ValueError('No unambiguous return route to the SSH client')
    route = routes[0]
    if route.get('dev') != interface:
        raise ValueError('SSH return path uses a different interface; recovery cannot be established')
    with open('/etc/nvue.d/startup.yaml', 'rb') as stream:
        startup = stream.read(8 * 1024 * 1024 + 1)
    if not startup or len(startup) > 8 * 1024 * 1024:
        raise ValueError('Saved NVUE configuration is empty or exceeds the recovery-check limit')
    snapshot.update(interface=interface, prefix=address['prefixlen'], vrf=vrf or 'default',
                    gateway=route.get('gateway', ''), startup_sha256=hashlib.sha256(startup).hexdigest(),
                    startup_b64=base64.b64encode(startup).decode('ascii'))
    return snapshot

def pin_startup(snapshot, operation_id):
    if os.geteuid() != 0:
        raise ValueError('The upgrade startup snapshot must be created by root')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', operation_id):
        raise ValueError('Invalid upgrade operation ID')
    data = base64.b64decode(snapshot['startup_b64'], validate=True)
    expected_hash = snapshot['startup_sha256']
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError('Approved startup snapshot checksum mismatch')
    # Root-created private directory avoids predictable-file/symlink races.
    # Copy the bytes already checked above, never re-read a changing source.
    directory = tempfile.mkdtemp(prefix='lldpq-upgrade-' + operation_id + '.', dir='/var/tmp')
    path = os.path.join(directory, 'startup.yaml')
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        with open(path, 'rb') as stream:
            if hashlib.sha256(stream.read()).hexdigest() != expected_hash:
                raise ValueError('Staged startup snapshot checksum mismatch')
        return path
    except BaseException:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        os.rmdir(directory)
        raise

try:
    snapshot = probe(sys.argv[1])
    if len(sys.argv) > 2:
        expected = json.loads(base64.b64decode(sys.argv[2]).decode('utf-8'))
        actual = {key: value for key, value in snapshot.items() if key != 'startup_b64'}
        if actual != expected:
            raise ValueError('Saved NVUE configuration or management path changed after validation; rerun upgrade precheck')
        if len(sys.argv) > 3:
            print(pin_startup(snapshot, sys.argv[3]))
        else:
            print('LLDPQ_MGMT_GUARD_OK')
    else:
        print('LLDPQ_MGMT_SNAPSHOT=' + json.dumps(snapshot))
except Exception as exc:
    print('IPv6 recovery check failed: ' + str(exc), file=sys.stderr)
    sys.exit(78)
'''


def probe_shell(expected=None, pin=False):
    """SSH_CONNECTION is passed explicitly because sudo normally removes it."""
    suffix = ''
    if expected is not None:
        encoded = base64.b64encode(json.dumps(expected, sort_keys=True).encode()).decode()
        suffix = ' ' + shlex.quote(encoded)
        if pin:
            suffix += ' "$OPERATION_ID"'
    return ('sudo -n python3 - "${SSH_CONNECTION:-}"' + suffix +
            " <<'LLDPQ_MGMT_PY'\n" + REMOTE_PROBE + '\nLLDPQ_MGMT_PY\n')


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _saved_config(document):
    # NVUE saves a YAML sequence containing metadata and a single `set` block.
    # Reject patch/unset sequences rather than guessing their final semantics.
    items = document if isinstance(document, list) else [document]
    blocks = []
    for item in items:
        if not isinstance(item, dict) or set(item) - {'header', 'set'}:
            raise ValueError('Unsupported NVUE startup structure; static management recovery cannot be verified')
        if 'set' in item:
            if not isinstance(item['set'], dict):
                raise ValueError('NVUE startup set block must be an object')
            blocks.append(item['set'])
    if len(blocks) != 1:
        raise ValueError('NVUE startup must contain one saved set block for recovery validation')
    return blocks[0]


def _ip(value):
    return ipaddress.ip_address(str(value).split('%')[0])


def _addresses(section):
    values = section.get('address', {})
    if not isinstance(values, (dict, list)):
        return []
    result = []
    for value in values:
        if '/' not in str(value):
            continue
        try:
            result.append(ipaddress.ip_interface(str(value)))
        except ValueError:
            continue
    return result


def _gateways(section):
    values = section.get('gateway', {})
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (dict, list)):
        return []
    result = []
    for value in values:
        try:
            result.append(_ip(value))
        except ValueError:
            continue
    return result


def _route_next_hops(route):
    """NVUE supports direct via and distance.<administrative-distance>.via."""
    route = _mapping(route)
    alternatives = []
    if 'via' in route:
        alternatives.append((1, _mapping(route['via'])))
    for distance, options in _mapping(route.get('distance')).items():
        try:
            distance = int(distance)
        except (TypeError, ValueError):
            continue
        if 1 <= distance <= 255:
            alternatives.append((distance, _mapping(_mapping(options).get('via'))))
    if not alternatives:
        return []
    lowest = min(distance for distance, _ in alternatives)
    return [entry for distance, hops in alternatives if distance == lowest for entry in hops.items()]


def validate_snapshot(snapshot, target):
    """Return a non-secret dispatch guard plus a concise evidence description."""
    import yaml
    if not isinstance(snapshot, dict):
        raise ValueError('Malformed management snapshot')
    server, client = _ip(snapshot.get('server', '')), _ip(snapshot.get('client', ''))
    try:
        literal_target = _ip(target)
    except ValueError:
        literal_target = None  # DNS/SSH alias: use the real SSH endpoint.
    if literal_target is not None and literal_target != server:
        raise ValueError('SSH server address differs from the selected management address')
    if snapshot.get('family') != server.version or server.version != client.version:
        raise ValueError('Inconsistent SSH transport addresses')
    if server.version == 4:
        return {'family': 4, 'server': str(server), 'client': str(client)}, 'IPv4 management transport'
    try:
        raw = base64.b64decode(snapshot.get('startup_b64', ''), validate=True)
        if not raw or len(raw) > 8 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != snapshot.get('startup_sha256'):
            raise ValueError('Invalid startup snapshot checksum')
        config = _saved_config(yaml.safe_load(raw))
    except (yaml.YAMLError, UnicodeError) as exc:
        raise ValueError('Saved startup.yaml could not be parsed') from exc
    interface = str(snapshot.get('interface', ''))
    interface_config = _mapping(_mapping(config.get('interface')).get(interface))
    # Only local interface address fields count. Neighbor/VRR/route occurrences
    # of the target IPv6 must never be treated as a saved management address.
    sections = [_mapping(interface_config.get(name)) for name in ('ip', 'ipv6')]
    addresses = [address for section in sections for address in _addresses(section)]
    matches = [address for address in addresses if address.ip == server and address.network.prefixlen == snapshot.get('prefix')]
    if not matches:
        raise ValueError('Management IPv6 and prefix are not saved on interface ' + interface + ' in startup.yaml')
    if _mapping(interface_config.get('link')).get('state') == 'down':
        raise ValueError('Saved management interface is administratively down')
    ipv6_sections = [_mapping(interface_config.get('ipv6')),
                     _mapping(_mapping(interface_config.get('ip')).get('ipv6'))]
    for section in ipv6_sections:
        for key in ('state', 'enable'):
            value = section.get(key)
            if value is False or (isinstance(value, str) and value.lower() in ('disabled', 'off', 'down')):
                raise ValueError('IPv6 is disabled on the saved management interface')
    # eth0 belongs to mgmt in the Cumulus default configuration; other
    # interfaces use the default VRF unless NVUE explicitly assigns one.
    saved_vrf = _mapping(interface_config.get('ip')).get('vrf', 'mgmt' if interface == 'eth0' else 'default')
    vrf = snapshot.get('vrf')
    if saved_vrf != vrf:
        raise ValueError('Saved management VRF does not match the active SSH interface')
    if vrf not in ('default', 'mgmt') and vrf not in _mapping(config.get('vrf')):
        raise ValueError('Management VRF is absent from startup.yaml')
    gateway_text = snapshot.get('gateway', '')
    gateway = _ip(gateway_text) if gateway_text else None
    candidates = [(address.network.prefixlen, None) for address in matches if client in address.network]
    candidates.extend((0, candidate) for section in sections for candidate in _gateways(section) if candidate.version == 6)
    static_routes = _mapping(_mapping(_mapping(_mapping(config.get('vrf')).get(vrf)).get('router')).get('static'))
    for prefix, route in static_routes.items():
        try:
            network = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if client not in network:
            continue
        # Remember a more-specific unsupported route, even without a usable
        # next hop. A saved default gateway must not hide a conflicting route.
        candidates.append((network.prefixlen, 'unsupported'))
        for next_hop, options in _route_next_hops(route):
            try:
                candidate = _ip(next_hop)
            except ValueError:
                continue
            options = _mapping(options)
            if (candidate.version == 6 and options.get('type', 'ipv6-address') == 'ipv6-address'
                    and options.get('interface', interface) == interface
                    and options.get('vrf', vrf) == vrf):
                candidates.append((network.prefixlen, candidate))
    longest = max((prefix for prefix, _ in candidates), default=-1)
    saved_path_matches = any(prefix == longest and candidate == gateway for prefix, candidate in candidates)
    if not gateway:
        if not saved_path_matches:
            raise ValueError('No saved connected/static return path to the SSH client')
        evidence = 'connected return path'
    else:
        # IPv6 next hops must be directly reachable on the restored interface;
        # recursive/dynamic routing needs a fuller topology recovery model.
        if not (gateway.is_link_local or any(gateway in address.network for address in addresses if address.version == 6)):
            raise ValueError('Management return gateway is not on a saved IPv6 subnet')
        if not saved_path_matches:
            raise ValueError('Active return gateway/route is not saved in NVUE; DHCPv6/RA or runtime routes alone are insufficient')
        evidence = 'saved static return gateway ' + str(gateway)
    expected = {key: snapshot[key] for key in ('family', 'server', 'client', 'interface', 'prefix', 'vrf', 'gateway', 'startup_sha256')}
    return expected, 'Static IPv6 %s/%s on %s (VRF %s), %s' % (server, snapshot['prefix'], interface, vrf, evidence)
