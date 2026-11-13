#!/usr/bin/env python3
"""The collector inventory is physical ports only.

``monitor.sh`` builds one interface list on the switch and walks it in the
carrier, optical and PFC sections.  The ``ip link`` filter was not anchored at
the end, so a VLAN sub-interface (``swp6.100``) entered the list although the
sysfs fallback and the PFC filter both rejected it.  A sub-interface copies
its parent's carrier, so one flapping port was reported once more per
sub-interface, and every sub-interface that was up cost a failing DOM read.

The tests run the remote script itself, taken from ``monitor.sh`` exactly as
the collector would send it, against a stand-in sysfs tree and stand-in
``timeout`` / ``date`` / ``sleep`` commands.  ``test_audit_col_optical_cage``
uses the same harness.
"""

import atexit
import functools
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from collections import namedtuple
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

MONITOR = SCRIPT_DIR / "monitor.sh"

Port = namedtuple("Port", "state device carrier alias", defaults=("up", True, 0, ""))
CollectorRun = namedtuple("CollectorRun", "stdout ethtool_calls clock")

# Stand-in for coreutils timeout on the switch.  It answers the two bounded
# commands these tests are about and lets every other one time out, so no
# real tool of the test machine is ever started:
#   ip link show     -> the sample in $LLDPQ_IP_LINK (absent: timed out, which
#                       sends the collector to its sysfs fallback)
#   ethtool -m <if>  -> one module per cage, behaviour in $LLDPQ_DOM/<cage>:
#                       "hang" (never answers; the clock moves by the limit),
#                       "once" (hangs for one read, answers from then on),
#                       "fail <seconds> [<next>]" (crawls, then an ordinary
#                       error; from then on behaves as <next>, if given),
#                       "empty" (instant error),
#                       "glitch [<next>]" (instant error for one read, then
#                       behaves as <next>; an EEPROM dump by default),
#                       "partial" (prints one line, then never answers),
#                       "odd" (a dump holding backslashes),
#                       "noisy" (a dump, but with an error status),
#                       otherwise an EEPROM dump.
TIMEOUT_STAND_IN = r"""#!/bin/sh
case "$*" in
    *" ip link show")
        [ -r "$LLDPQ_IP_LINK" ] || exit 124
        cat "$LLDPQ_IP_LINK"
        exit 0 ;;
    *" ethtool -m "*)
        limit=1
        for value do
            case "$value" in [0-9]*s) limit=${value%s} ;; esac
            interface=$value
        done
        printf '%s\n' "$interface" >> "$LLDPQ_ETHTOOL_CALLS"
        cage=$interface
        case "$interface" in swp[0-9]*s[0-9]*) cage=${interface%s[0-9]*} ;; esac
        mode=data
        cost=0
        next=""
        [ -r "$LLDPQ_DOM/$cage" ] &&
            read -r mode cost next < "$LLDPQ_DOM/$cage"
        read -r now < "$LLDPQ_CLOCK"
        case "$mode" in
            hang) echo $((now + limit)) > "$LLDPQ_CLOCK"; exit 124 ;;
            once)
                echo data > "$LLDPQ_DOM/$cage"
                echo $((now + limit)) > "$LLDPQ_CLOCK"
                exit 124 ;;
            fail)
                [ -n "$next" ] && echo "$next" > "$LLDPQ_DOM/$cage"
                echo $((now + cost)) > "$LLDPQ_CLOCK"
                exit 1 ;;
            empty) exit 1 ;;
            glitch) echo "${cost:-data}" > "$LLDPQ_DOM/$cage"; exit 1 ;;
            partial)
                echo "	Identifier                                : 0x18 (QSFP-DD)"
                echo $((now + limit)) > "$LLDPQ_CLOCK"
                exit 124 ;;
        esac
        echo "	Identifier                                : 0x18 (QSFP-DD)"
        echo "	Vendor name                               : ACME"
        echo "	Vendor SN                                 : SN-$cage"
        [ "$mode" = odd ] &&
            printf '%s\n' '	Vendor PN                                 : A\\\\B'
        [ "$mode" = noisy ] && exit 1
        exit 0 ;;
esac
exit 124
"""

# The collector measures DOM reads with `date +%s`.  A file-backed clock that
# only hung reads, crawling reads and sleeps move keeps the timing exact and
# the tests instant.
DATE_STAND_IN = r"""#!/bin/sh
case "$1" in
    +%s) cat "$LLDPQ_CLOCK" ;;
    *) exec /bin/date "$@" ;;
esac
"""

SLEEP_STAND_IN = r"""#!/bin/sh
read -r now < "$LLDPQ_CLOCK"
echo $((now + $1)) > "$LLDPQ_CLOCK"
"""

# GNU `sort -V` is not available on every test machine.  For interface names
# the version order is the byte order of a key in which every run of digits
# is padded to one width and every other non-letter sorts after the letters.
SORT_STAND_IN = r"""#!/bin/sh
[ "$1" = -V ] || exec /usr/bin/sort "$@"
shift
awk '{
    key = ""
    rest = $0
    while (match(rest, /[0-9]+/)) {
        text = substr(rest, 1, RSTART - 1)
        number = sprintf("%012d", substr(rest, RSTART, RLENGTH))
        rest = substr(rest, RSTART + RLENGTH)
        gsub(/[^A-Za-z]/, "~&", text)
        key = key text number
    }
    gsub(/[^A-Za-z]/, "~&", rest)
    print key rest "\t" $0
}' "$@" | LC_ALL=C /usr/bin/sort -t "	" -k 1,1 | cut -f 2-
"""

# The collector keeps its snapshot in a directory `mktemp -d` names.  The
# stand-in can make entries of that directory unwritable for the collector by
# creating them as directories first ($LLDPQ_SNAPSHOT_BLOCKED, one name per
# word).
MKTEMP_STAND_IN = r"""#!/bin/sh
made=$(/usr/bin/mktemp "$@") || exit
case "$*" in
    "-d "*lldpq-monitor.*)
        for name in $LLDPQ_SNAPSHOT_BLOCKED; do
            mkdir "$made/$name"
        done ;;
esac
printf '%s\n' "$made"
"""

CLOCK_START = 1000


@functools.lru_cache(maxsize=None)
def remote_script(scope, budget=120, port_timeout=5):
    """Return the remote script as the local shell would hand it to ssh."""
    source = MONITOR.read_text(encoding="utf-8")
    start = source.index(
        '    timeout "$ssh_umbrella_timeout" ssh -o ConnectTimeout='
        '"$connect_timeout" $SSH_OPTS'
    )
    end = source.index("\n    local ssh_status=$?", start)
    command = textwrap.dedent(source[start:end])
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "timeout").write_text(
            "#!/bin/sh\n[ \"$1\" = 300 ] || exit 91\nshift\nexec \"$@\"\n",
            encoding="utf-8",
        )
        (root / "ssh").write_text(
            "#!/bin/sh\nfor value do remote=$value; done\n"
            "printf '%s\\n' \"$remote\" > \"$LLDPQ_REMOTE_CAPTURE\"\n",
            encoding="utf-8",
        )
        (root / "timeout").chmod(0o755)
        (root / "ssh").chmod(0o755)
        capture = root / "remote.sh"
        assignments = "\n".join(
            (
                'SSH_OPTS=""',
                'user="tester"',
                'device="switch.example"',
                'hostname="leaf1"',
                'connect_timeout="5"',
                'SKIP_OPTICAL="false"',
                'SKIP_L1="false"',
                'SKIP_DUPLICATE="false"',
                'SKIP_EVPN_MH="false"',
                'SKIP_PFC_ECN="false"',
                'ssh_umbrella_timeout="300"',
                'PFC_ECN_COLLECTION_BUDGET_SECONDS="60"',
                'PFC_ECN_PORT_TIMEOUT_SECONDS="5"',
                'PFC_ECN_MAX_PARALLEL="4"',
                f'OPTICAL_COLLECTION_BUDGET_SECONDS="{budget}"',
                f'OPTICAL_PORT_TIMEOUT_SECONDS="{port_timeout}"',
                'MONITOR_COMMAND_TIMEOUT_SECONDS="20"',
                'MONITOR_TIMING="false"',
                f'MONITOR_SCOPE="{scope}"',
                f'raw_file="{root / "raw.txt"}"',
                f'ssh_error_file="{root / "ssh.stderr"}"',
            )
        )
        env = dict(os.environ)
        env["PATH"] = str(root) + os.pathsep + env.get("PATH", "")
        env["LLDPQ_REMOTE_CAPTURE"] = str(capture)
        interpolated = subprocess.run(
            ["/bin/bash", "-c", assignments + "\n" + command],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        if interpolated.returncode != 0:
            raise AssertionError(interpolated.stderr)
        return capture.read_text(encoding="utf-8")


@functools.lru_cache(maxsize=None)
def stand_in_bin():
    """One directory of stand-in commands for the whole test run.

    Each run is steered through its environment, so the commands can be
    shared; writing them once also spares the per-file first-run check some
    systems apply to a new executable.
    """
    temporary = tempfile.TemporaryDirectory()
    atexit.register(temporary.cleanup)
    bin_root = Path(temporary.name)
    for name, body in (
        ("timeout", TIMEOUT_STAND_IN),
        ("date", DATE_STAND_IN),
        ("sleep", SLEEP_STAND_IN),
        ("sort", SORT_STAND_IN),
        ("mktemp", MKTEMP_STAND_IN),
    ):
        (bin_root / name).write_text(body, encoding="utf-8")
        (bin_root / name).chmod(0o755)
    return bin_root


def ip_link_sample(names):
    """`ip link show` output listing the names in the given order."""
    lines = []
    for index, name in enumerate(names, start=3):
        shown = name
        if "." in name:
            shown = f"{name}@{name.split('.', 1)[0]}"
        lines.append(
            f"{index}: {shown}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216 "
            "qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000"
        )
        lines.append(
            f"    link/ether 02:00:00:00:00:{index % 256:02x} "
            "brd ff:ff:ff:ff:ff:ff"
        )
    return "\n".join(lines) + "\n"


def run_collector(test, scope, ports, *, ip_link=True, dom=None,
                  budget=120, port_timeout=5, blocked=()):
    """Run the remote collector for one scope and return what it printed.

    ``ports`` maps interface name to ``Port``; the mapping order is the
    ``ip link`` order.  ``ip_link=False`` withholds the ``ip`` answer.
    ``dom`` maps a cage (``swp5``) to its module behaviour.  ``blocked``
    names snapshot files the collector must fail to write.
    """
    temporary = tempfile.TemporaryDirectory()
    test.addCleanup(temporary.cleanup)
    root = Path(temporary.name)
    remote = remote_script(scope, budget, port_timeout)

    net_root = root / "sys-class-net"
    for name, port in ports.items():
        port_root = net_root / name
        port_root.mkdir(parents=True)
        (port_root / "operstate").write_text(port.state + "\n", encoding="utf-8")
        (port_root / "carrier_changes").write_text(
            f"{port.carrier}\n", encoding="utf-8"
        )
        (port_root / "ifalias").write_text(
            port.alias + "\n" if port.alias else "", encoding="utf-8"
        )
        if port.device:
            (port_root / "device").mkdir()
    test.assertIn("_lldpq_net_class_root=/sys/class/net", remote)
    remote = remote.replace(
        "_lldpq_net_class_root=/sys/class/net",
        f'_lldpq_net_class_root="{net_root}"',
    )

    dom_root = root / "dom"
    dom_root.mkdir()
    for cage, behaviour in (dom or {}).items():
        (dom_root / cage).write_text(behaviour + "\n", encoding="utf-8")
    clock = root / "clock"
    clock.write_text(f"{CLOCK_START}\n", encoding="utf-8")
    calls = root / "ethtool.calls"
    calls.write_text("", encoding="utf-8")
    sample = root / "ip-link.txt"
    if ip_link:
        sample.write_text(ip_link_sample(ports), encoding="utf-8")

    collected = subprocess.run(
        ["/bin/sh"],
        input=remote,
        env={
            "PATH": str(stand_in_bin()) + os.pathsep + "/usr/bin:/bin",
            "LLDPQ_IP_LINK": str(sample),
            "LLDPQ_DOM": str(dom_root),
            "LLDPQ_CLOCK": str(clock),
            "LLDPQ_ETHTOOL_CALLS": str(calls),
            "LLDPQ_SNAPSHOT_BLOCKED": " ".join(blocked),
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    test.assertEqual(collected.returncode, 0, collected.stderr)
    return CollectorRun(
        collected.stdout,
        calls.read_text(encoding="utf-8").split(),
        int(clock.read_text(encoding="utf-8")) - CLOCK_START,
    )


def section(stdout, name):
    return stdout.split(f"==={name}_START===\n", 1)[1].split(
        f"==={name}_END===", 1
    )[0]


PHYSICAL = ("swp1", "swp2", "swp6", "swp6s0", "swp6s1", "swp10")
SUB_INTERFACES = ("swp6.100", "swp6.200", "swp6s1.300", "swp2.50")
# Names no filter may take for a port, whatever a driver or an operator
# called them.
MALFORMED = ("swp3s", "swp4s1s2", "swp7x", "swp8s0x", "swp11_2")


def switch_ports():
    """A switch with routed sub-interfaces on front-panel ports.

    A VLAN device has no device link and, as in the kernel, shows the
    carrier counter of its parent.
    """
    ports = {
        "swp1": Port(carrier=3, alias="uplink spine1"),
        "swp2": Port(alias="firewall trunk"),
        "swp6": Port(carrier=14, alias="border hand-off"),
        "swp6s0": Port(carrier=1),
        "swp6s1": Port(carrier=2),
        "swp10": Port(state="down"),
        "bond1": Port(device=False),
        "swp6.100": Port(device=False, carrier=14, alias="vrf RED hand-off"),
        "swp6.200": Port(device=False, carrier=14, alias="vrf BLUE hand-off"),
        "swp6s1.300": Port(device=False, carrier=2),
        "swp2.50": Port(device=False, alias="fw <inside>"),
    }
    for name in MALFORMED:
        ports[name] = Port(device=False)
    return ports


def carrier_names(run):
    body = section(run.stdout, "CARRIER_DATA")
    return [line.rsplit(":", 1)[0] for line in body.splitlines() if line]


def optical_names(run):
    return re.findall(
        r"^--- Interface: (\S+)$", section(run.stdout, "OPTICAL_DATA"), re.M
    )


def pfc_names(run):
    return re.findall(
        r"^__LLDPQ_PFC_ECN_PORT_START__:(\S+)$",
        section(run.stdout, "PFC_ECN_DATA"),
        re.M,
    )


def port_status_rows(run):
    table = run.stdout.split("Port Status", 1)[1].split(
        "Interface IP Addresses", 1
    )[0]
    rows = {}
    for line in table.splitlines():
        match = re.match(r'<span style="color:steelblue;">(\S+)\s*</span>', line)
        if match:
            rows[match.group(1)] = line.rsplit("</span> ", 1)[1]
    return rows


class PhysicalPortInventoryTests(unittest.TestCase):
    def test_sub_interfaces_stay_out_of_the_carrier_section(self):
        run = run_collector(self, "flap", switch_ports())

        self.assertEqual(carrier_names(run), list(PHYSICAL))
        # One physical flap counter, reported once.
        self.assertEqual(
            section(run.stdout, "CARRIER_DATA").count(":14\n"), 1, run.stdout
        )

    def test_sub_interfaces_get_no_optical_block_and_cost_no_dom_read(self):
        run = run_collector(self, "optical", switch_ports())

        self.assertCountEqual(optical_names(run), PHYSICAL)
        self.assertEqual(
            [name for name in run.ethtool_calls if "." in name], []
        )

    def test_abandoned_sweep_names_no_sub_interface(self):
        # Every module hangs, so the section is abandoned and the tail is
        # published as unvisited: that tail is ports, never sub-interfaces.
        ports = switch_ports()
        dom = {name: "hang" for name in ("swp1", "swp2", "swp6", "swp10")}
        run = run_collector(self, "optical", ports, dom=dom)

        markers = re.findall(
            r"__LLDPQ_COLLECTION_ERROR__:OPTICAL_\w+:(\S+)", run.stdout
        )
        self.assertTrue(markers)
        self.assertEqual([name for name in markers if "." in name], [])

    def test_ip_link_inventory_sysfs_fallback_and_pfc_list_agree(self):
        ports = switch_ports()
        inventories = {
            "ip link": carrier_names(run_collector(self, "flap", ports)),
            "sysfs fallback": carrier_names(
                run_collector(self, "flap", ports, ip_link=False)
            ),
            "pfc": pfc_names(run_collector(self, "pfc-ecn", ports)),
            "pfc after the fallback": pfc_names(
                run_collector(self, "pfc-ecn", ports, ip_link=False)
            ),
        }

        for label, names in inventories.items():
            self.assertEqual(sorted(names), sorted(PHYSICAL), label)

    def test_optical_sweep_walks_the_same_inventory(self):
        ports = switch_ports()
        with_ip = run_collector(self, "optical", ports)
        without_ip = run_collector(self, "optical", ports, ip_link=False)

        self.assertCountEqual(optical_names(with_ip), PHYSICAL)
        self.assertCountEqual(optical_names(without_ip), PHYSICAL)


class PortStatusTableTests(unittest.TestCase):
    """The table is the one consumer that lists sub-interfaces.

    A routed sub-interface carries its own description and state, so the
    table keeps a wider list of its own instead of widening the inventory.
    """

    def test_table_still_lists_sub_interfaces_with_their_description(self):
        ports = switch_ports()
        rows = port_status_rows(run_collector(self, "all", ports))

        # Exactly the names the table listed before the inventory was
        # narrowed: everything that starts like a front-panel port.
        expected = [
            name for name in ports if re.match(r"swp[0-9]+[s0-9]*", name)
        ]
        self.assertCountEqual(rows, expected)
        for name in SUB_INTERFACES:
            self.assertIn(name, rows)
        self.assertEqual(rows["swp6.100"], "vrf RED hand-off")
        self.assertEqual(rows["swp6s1.300"], "No description")
        self.assertEqual(rows["swp2.50"], "fw &lt;inside&gt;")
        self.assertEqual(rows["swp1"], "uplink spine1")

    def test_full_run_keeps_them_out_of_every_per_port_section(self):
        run = run_collector(self, "all", switch_ports())

        self.assertIn("swp6.100", port_status_rows(run))
        self.assertEqual(carrier_names(run), list(PHYSICAL))
        self.assertCountEqual(optical_names(run), PHYSICAL)
        self.assertCountEqual(pfc_names(run), PHYSICAL)

    def test_sysfs_fallback_table_lists_the_physical_ports(self):
        run = run_collector(self, "all", switch_ports(), ip_link=False)

        self.assertCountEqual(port_status_rows(run), PHYSICAL)
        self.assertEqual(sorted(carrier_names(run)), sorted(PHYSICAL))

    # `ip link` order and sysfs glob order of one switch; the table shows
    # neither.
    UNORDERED = ("swp10", "swp2", "swp1s1", "swp1s0", "swp2.50", "swp1s10")

    def test_table_rows_are_in_version_order(self):
        ports = {
            name: Port(device="." not in name) for name in self.UNORDERED
        }
        run = run_collector(self, "all", ports)

        self.assertEqual(
            list(port_status_rows(run)),
            ["swp1s0", "swp1s1", "swp1s10", "swp2", "swp2.50", "swp10"],
        )

    def test_sysfs_fallback_table_rows_are_in_version_order(self):
        ports = {
            name: Port(device="." not in name) for name in self.UNORDERED
        }
        run = run_collector(self, "all", ports, ip_link=False)

        self.assertEqual(
            list(port_status_rows(run)),
            ["swp1s0", "swp1s1", "swp1s10", "swp2", "swp10"],
        )


if __name__ == "__main__":
    unittest.main()
