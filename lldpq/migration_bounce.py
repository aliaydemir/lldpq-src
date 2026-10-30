"""Prepare an immutable Ansible port-bounce job from a persisted migration."""
import json
from pathlib import Path
import re
import sys

import yaml


# Ansible's async wrapper runs this on the switch independently of the
# controller/SSH connection. Always attempt ifup, including partial ifdown
# failures, and report failure if either side of the bounce failed.
BOUNCE_SCRIPT = r'''set -u
set -- {{ lldpq_bounce_ports[inventory_hostname] | map('quote') | join(' ') }}
restore_ports() {
    local attempt
    for attempt in 1 2 3; do
        if timeout --kill-after=5s 30s /usr/sbin/ifup "$@"; then
            return 0
        fi
        sleep 2
    done
    echo "ERROR: ifup failed after 3 attempts: $*" >&2
    return 1
}
trap 'trap - EXIT HUP INT TERM; restore_ports "$@"; exit 1' EXIT HUP INT TERM
echo "ifdown: $*"
timeout --kill-after=5s 30s /usr/sbin/ifdown "$@"
down_rc=$?
if [ "$down_rc" -eq 0 ]; then sleep 7; fi
echo "ifup: $*"
restore_ports "$@"
up_rc=$?
trap - EXIT HUP INT TERM
if [ "$up_rc" -ne 0 ]; then exit "$up_rc"; fi
if [ "$down_rc" -ne 0 ]; then
    echo "ERROR: ifdown failed; ifup recovery succeeded" >&2
    exit "$down_rc"
fi
echo "Port bounce complete; ifup succeeded."
'''


def prepare(root, plan_id, limit):
    root = Path(root)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", plan_id):
        raise ValueError("Invalid migration plan ID")
    plan = json.loads((root / ".migrations" / (plan_id + ".json")).read_text())
    if plan.get("id") != plan_id:
        raise ValueError("Migration plan ID does not match its record")
    hosts = [host for host in limit.split(",") if host and host != "localhost"]
    if not hosts or len(set(hosts)) != len(hosts):
        raise ValueError("No devices or duplicate devices in bounce request")
    port_map = {}
    for host in hosts:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", host):
            raise ValueError("Invalid migration host")
        applied = plan.get("changes", {}).get(host, {}).get("applied", [])
        if not applied:
            raise ValueError(f"No applied migration ports for {host}")
        path = root / "inventory" / "host_vars" / (host + ".yaml")
        if not path.exists():
            path = path.with_suffix(".yml")
        config = yaml.safe_load(path.read_text()) or {}
        ports = []
        for entry in applied:
            section, port = entry.get("section"), entry.get("name")
            if section not in ("interfaces", "bonds") or not isinstance(port, str) or \
                    not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", port):
                raise ValueError(f"Invalid migration port for {host}")
            current = (config.get(section) or {}).get(port)
            if not isinstance(current, dict) or \
                    (current.get("sw_port_profile") or "") != (entry.get("new") or ""):
                raise ValueError(f"Migration changed since apply: {host}/{port}; refresh the plan")
            if port not in ports:
                ports.append(port)
        port_map[host] = ports
    return [{
        "name": f"Restore ports after migration {plan_id}",
        "hosts": hosts, "gather_facts": False, "become": True,
        "vars": {"lldpq_bounce_ports": port_map},
        "tasks": [{
            "name": "Bounce ports with remote ifup recovery",
            "ansible.builtin.shell": BOUNCE_SCRIPT,
            "args": {"executable": "/bin/bash"},
            "async": 240, "poll": 2,
            "register": "lldpq_bounce_result",
        }],
    }, {
        # Ansible otherwise returns rc=0 when no inventory host matches. A
        # successful job requires an observed result from every selected host.
        "name": "Confirm restoration on every selected switch",
        "hosts": "localhost", "connection": "local",
        "gather_facts": False, "become": False,
        "tasks": [{
            "name": "Require a successful ifup result for every device",
            "ansible.builtin.assert": {
                "that": ["item in hostvars",
                         "(hostvars[item].lldpq_bounce_result | default({})).get('rc', 1) == 0"],
                "fail_msg": "Port restoration was not confirmed for {{ item }}",
            },
            "loop": hosts,
        }],
    }]


if __name__ == "__main__":
    try:
        print(json.dumps(prepare(*sys.argv[1:])))
    except Exception as exc:
        print(f"Cannot prepare port bounce: {exc}", file=sys.stderr)
        sys.exit(1)
