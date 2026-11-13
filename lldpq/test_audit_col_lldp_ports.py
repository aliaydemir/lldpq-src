#!/usr/bin/env python3
"""VLAN sub-interfaces are not ports in the LLDP port sections.

``check-lldp.sh`` reports status, speed, MTU and link parameters for every
physical data interface.  A Cumulus ``swp`` device is kept even when sysfs
shows no device link, and a VLAN sub-interface (``swp6.100``) has none
either, so the ``swp*`` arm of all four loops took it for a port: it was
counted among the ports seen and in the MTU distribution, and cost two
ethtool calls per run while its parent was up.

The remote script is taken from ``check-lldp.sh`` as the local shell would
hand it to ssh and run against a stand-in sysfs tree.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

CHECK_LLDP = SCRIPT_DIR / "check-lldp.sh"

# name -> (operstate, carrier, has a device link)
INTERFACES = {
    # Cumulus front-panel ports whose driver exposes no device link.
    "swp1": ("up", "1", False),
    "swp2": ("up", "1", False),
    "swp6": ("up", "1", False),
    "swp6s0": ("up", "1", False),
    "swp6s1": ("up", "1", False),
    "swp10": ("down", "0", False),
    # A host NIC is kept through its device link.
    "enp3s0f0np0": ("up", "1", True),
    # Routed sub-interfaces of the ports above.
    "swp6.100": ("up", "1", False),
    "swp6.200": ("up", "1", False),
    "swp6s1.300": ("up", "1", False),
    "swp2.50": ("up", "1", False),
    # Never ports, before or after.
    "bond1": ("up", "1", False),
    "peerlink.4094": ("up", "1", False),
    "lo": ("unknown", "1", False),
}
PORTS = ["swp1", "swp2", "swp6", "swp6s0", "swp6s1", "swp10", "enp3s0f0np0"]
CARRIER_UP = [name for name in PORTS if name != "swp10"]


def remote_script(root):
    """Return the remote script as the local shell would hand it to ssh."""
    source = CHECK_LLDP.read_text(encoding="utf-8")
    start = source.index(
        'timeout 180 ssh -o ConnectTimeout="$connect_timeout" $SSH_OPTS '
        '-T -q "$user@$device" "'
    )
    end = source.index('\n    " > "$temporary_file"', start)
    command = source[start:end] + '\n    "'
    stubs = root / "interpolate"
    stubs.mkdir()
    (stubs / "timeout").write_text(
        "#!/bin/sh\n[ \"$1\" = 180 ] || exit 91\nshift\nexec \"$@\"\n",
        encoding="utf-8",
    )
    (stubs / "ssh").write_text(
        "#!/bin/sh\nfor value do remote=$value; done\n"
        "printf '%s\\n' \"$remote\" > \"$LLDPQ_REMOTE_CAPTURE\"\n",
        encoding="utf-8",
    )
    for stub in stubs.iterdir():
        stub.chmod(0o755)
    capture = root / "remote.sh"
    assignments = "\n".join(
        (
            'SSH_OPTS=""',
            'user="tester"',
            'device="switch.example"',
            'hostname="leaf1"',
            'connect_timeout="5"',
        )
    )
    env = dict(os.environ)
    env["PATH"] = str(stubs) + os.pathsep + env.get("PATH", "")
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


def section(stdout, name):
    body = stdout.split(f"==={name}_START===\n", 1)[1].split(
        f"==={name}_END===", 1
    )[0]
    return [line for line in body.splitlines() if line]


class LldpPortSectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        root = Path(temporary.name)
        remote = remote_script(root)

        net_root = root / "sys-class-net"
        for name, (state, carrier, device) in INTERFACES.items():
            port_root = net_root / name
            port_root.mkdir(parents=True)
            (port_root / "operstate").write_text(state + "\n", encoding="utf-8")
            (port_root / "carrier").write_text(carrier + "\n", encoding="utf-8")
            (port_root / "speed").write_text("100000\n", encoding="utf-8")
            (port_root / "mtu").write_text("9216\n", encoding="utf-8")
            if device:
                (port_root / "device").mkdir()
        # The four port loops, and nothing else, walk the sysfs tree.
        assert remote.count("/sys/class/net/*") == 4, remote
        remote = remote.replace("/sys/class/net/*", f"{net_root}/*")

        bin_root = root / "bin"
        bin_root.mkdir()
        cls.ethtool_calls = root / "ethtool.calls"
        cls.ethtool_calls.write_text("", encoding="utf-8")
        stand_ins = {
            # `sudo lldpctl`: an empty, successful LLDP answer.
            "sudo": "#!/bin/sh\nexit 0\n",
            "ethtool": (
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$LLDPQ_ETHTOOL_CALLS\"\n"
                "case \"$1\" in\n"
                "    --show-fec) echo 'Active FEC encoding: RS' ;;\n"
                "    *) echo '	Auto-negotiation: off' ;;\n"
                "esac\n"
            ),
            # GNU `sort -V` is not available on every test machine.
            "sort": "#!/bin/sh\n[ \"$1\" = -V ] && shift\nexec /usr/bin/sort \"$@\"\n",
        }
        for name, body in stand_ins.items():
            (bin_root / name).write_text(body, encoding="utf-8")
            (bin_root / name).chmod(0o755)

        collected = subprocess.run(
            ["/bin/sh"],
            input=remote,
            env={
                "PATH": str(bin_root) + os.pathsep + "/usr/bin:/bin",
                "LLDPQ_ETHTOOL_CALLS": str(cls.ethtool_calls),
            },
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert collected.returncode == 0, collected.stderr
        cls.stdout = collected.stdout

    def names(self, name):
        return [line.split()[0] for line in section(self.stdout, name)]

    def test_status_section_lists_ports_only(self):
        self.assertCountEqual(self.names("PORT_STATUS"), PORTS)
        self.assertIn("swp6 UP", section(self.stdout, "PORT_STATUS"))
        self.assertIn("swp10 DOWN", section(self.stdout, "PORT_STATUS"))
        self.assertIn("enp3s0f0np0 UP", section(self.stdout, "PORT_STATUS"))

    def test_speed_section_lists_ports_only(self):
        self.assertCountEqual(self.names("PORT_SPEED"), PORTS)

    def test_mtu_section_lists_ports_only(self):
        self.assertCountEqual(self.names("PORT_MTU"), PORTS)

    def test_link_section_lists_ports_only_and_queries_no_sub_interface(self):
        self.assertCountEqual(self.names("PORT_LINK"), CARRIER_UP)
        calls = self.ethtool_calls.read_text(encoding="utf-8").splitlines()
        self.assertCountEqual(
            [call.split()[-1] for call in calls], CARRIER_UP * 2
        )

    def test_collection_stays_complete(self):
        self.assertNotIn("__LLDPQ_LLDP_COLLECTION_ERROR__", self.stdout)
        self.assertIn("===PORT_STATUS_END===", self.stdout)


if __name__ == "__main__":
    unittest.main()
