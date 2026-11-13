#!/usr/bin/env python3
"""Ask-AI commands pass two layers; they must not disagree.

Layer 1 is html/ai_command_policy.py (also the [DRYRUN:] verdict). Layer 2 is
the generic validator of the run-device-command action in html/fabric-api.sh,
which re-checks every Ask-AI command before SSH. A command that layer 1 allows
and layer 2 rejects reaches the model as "Command not in whitelist" after the
policy (and the dry run) said it was fine.

The validator block is taken verbatim from fabric-api.sh and executed in a
subprocess, so these tests follow the shipped code.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "html"
FABRIC_API = (HTML / "fabric-api.sh").read_text(encoding="utf-8")
POLICY_TESTS = (ROOT / "lldpq" / "test_ai_command_policy.py").read_text(
    encoding="utf-8"
)

sys.path.insert(0, str(HTML))

import ai_command_policy  # noqa: E402
from ai_command_policy import validate_ai_readonly_command  # noqa: E402
from test_ai_api_contract import load_symbols  # noqa: E402

_ARM = FABRIC_API.index("    run-device-command)")
_START = FABRIC_API.index("python3 << 'PYTHON_END'\n", _ARM) + len(
    "python3 << 'PYTHON_END'\n"
)
# Everything up to the device lookup is command validation; reaching the end
# of this block without a JSON error means the runner would execute the command.
_END = FABRIC_API.index(
    "# Validate device name (must be a valid hostname pattern)", _START
)
RUNNER_VALIDATOR = FABRIC_API[_START:_END]

DRIVER = r"""
import contextlib, io, json, os, sys
request = json.load(sys.stdin)
block = compile(request["block"], "run-device-command", "exec")
verdicts = []
for command, policy in request["cases"]:
    os.environ["POST_DATA"] = json.dumps(
        {"device": "leaf-01", "command": command, "policy": policy}
    )
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            exec(block, {"__name__": "run_device_command", "exit": sys.exit})
    except SystemExit:
        pass
    text = output.getvalue().strip()
    verdicts.append(
        json.loads(text.splitlines()[-1]).get("error", "rejected") if text else None
    )
json.dump(verdicts, sys.stdout)
"""


def runner_verdicts(commands, policy):
    """Return {command: None when the runner accepts it, else its error}."""
    commands = list(commands)
    environment = {
        key: value for key, value in os.environ.items() if key != "SCRIPT_FILENAME"
    }
    environment["WEB_ROOT"] = str(HTML)
    result = subprocess.run(
        [sys.executable, "-c", DRIVER],
        input=json.dumps(
            {"block": RUNNER_VALIDATOR, "cases": [[c, policy] for c in commands]}
        ),
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    return dict(zip(commands, json.loads(result.stdout)))


def commands_the_policy_tests_expect_allowed():
    """Every command test_ai_command_policy.py passes to assert_allowed."""

    def is_assert_allowed(node):
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "assert_allowed"
        )

    commands = []
    for node in ast.walk(ast.parse(POLICY_TESTS)):
        if is_assert_allowed(node) and isinstance(node.args[0], ast.Constant):
            commands.append(node.args[0].value)
        elif isinstance(node, ast.For) and any(
            is_assert_allowed(child) for child in ast.walk(node)
        ):
            commands.extend(element.value for element in node.iter.elts)
    return commands


# The three read-only forms the KB runbooks teach (ai_kb.py ber-fec and
# mtu-fabric sections). They are the reason both layers must agree by
# accepting, not by the policy withdrawing them.
KB_RUNBOOK_FORMS = (
    "ethtool --show-fec swp1",
    "sudo ethtool --show-fec swp1s2",
    "ip -d link show swp1",
    "cat /sys/class/net/swp1/mtu",
)

# One or more spellings of every family, flag and option the policy offers.
REPRESENTATIVE = KB_RUNBOOK_FORMS + (
    # nv
    "nv show interface",
    "nv show interface swp1 link",
    "nv show interface swp1 -o json",
    "nv show vrf default router bgp neighbor",
    "sudo nv show interface",
    "nv config show",
    "nv config diff",
    "nv config find bgp",
    "sudo nv config show",
    "sudo nv config diff",
    "sudo nv config find bgp",
    # vtysh, with the output modifiers vtysh itself interprets
    "sudo vtysh -c 'show bgp summary'",
    "vtysh -c 'show bgp summary'",
    'sudo vtysh -c "show bgp l2vpn evpn summary"',
    "sudo vtysh -c 'show bgp summary json'",
    "sudo vtysh -c 'show bgp summary | include Estab'",
    "sudo vtysh -c 'show ip route | include ^B'",
    'sudo vtysh -c "show bgp neighbors | include ^BGP neighbor"',
    "sudo vtysh -c 'show running-config | section router bgp'",
    "sudo vtysh -c 'show bgp neighbors | begin swp1'",
    "sudo vtysh -c 'show interface swp1 | exclude down'",
    # ethtool
    "ethtool swp1",
    "ethtool -m swp1",
    "ethtool -S swp1",
    "ethtool -i swp1",
    "sudo ethtool -m swp1",
    "/sbin/ethtool --show-fec swp1",
    "sudo /sbin/ethtool --show-fec swp1",
    # ip
    "ip link",
    "ip link show swp1",
    "ip link show type vxlan",
    "ip addr show dev swp1",
    "ip -4 addr show",
    "ip -6 route show",
    "ip route show vrf mgmt",
    "ip route get 10.0.0.1",
    "ip neigh show",
    "sudo ip link show",
    "ip -d link show",
    "ip -d -6 addr show",
    "ip -d -4 route show",
    "sudo ip -d link show swp1",
    # bridge
    "bridge fdb",
    "bridge fdb show dev swp1",
    "bridge vlan show",
    "bridge vlan list",
    "/sbin/bridge fdb show",
    "sudo bridge fdb show",
    "sudo /sbin/bridge vlan show",
    # lldpctl
    "lldpctl",
    "lldpctl swp1",
    "lldpctl -f json",
    "lldpctl -f keyvalue swp1",
    "sudo lldpctl -f json swp1",
    # files and layer-1 tools
    "cat /proc/net/bonding/bond1",
    "sudo cat /proc/net/bonding/bond1",
    "sudo cat /sys/class/net/swp1/mtu",
    "cat /sys/class/net/swp1s0/mtu",
    "l1-show swp1",
    "sudo l1-show swp1",
    "clagctl",
    "clagctl status",
    "sudo clagctl",
    "sudo clagctl status",
    "nvt",
    "/usr/local/bin/nvt",
    # journalctl (bounded) and dmesg
    "journalctl --no-pager -n 200",
    "journalctl --no-pager --lines=50",
    "sudo journalctl --no-pager -n 100 -u frr",
    "sudo journalctl -u frr -p warning -n 80 --no-pager",
    "sudo journalctl -k -g 'Link is' -n 100 --no-pager",
    'journalctl --no-pager -n 100 --since "1 hour ago"',
    "journalctl --no-pager -n 100 -u frr --since=today",
    "journalctl --no-pager -n 100 -t kernel -o short-iso",
    "journalctl --no-pager -n 100 --utc --reverse --quiet --merge -b --boot -x --catalog --all",
    "journalctl --no-pager -n 100 --dmesg SYSLOG_IDENTIFIER=frr",
    "journalctl --no-pager -n 100 --until now --unit frr --priority 3 --output cat --grep err --identifier bgpd",
    "journalctl --no-pager -n 100 -u switchd -S yesterday -U now",
    "dmesg",
    "dmesg -T",
    "sudo dmesg -T --level=err,warn",
    "dmesg --ctime --decode --nopager",
    "dmesg --reltime -x -P",
    "dmesg --notime --facility=kern --color=never",
    # system
    "uptime",
    "sudo uptime",
    "free",
    "free -m",
    "free -b -k -g -h --si -t -w --wide",
    "sudo free -m",
    "df",
    "df -h /",
    "df -H -i -T --total",
    "sudo df -h",
    "sensors",
    "sudo sensors",
    "smonctl",
    "sudo smonctl",
    "decode-syseeprom",
    "sudo decode-syseeprom",
    "cl-resource-query",
    "sudo cl-resource-query",
)

# Read-only by intent, but they carry a word the runner forbids anywhere in a
# command. The policy must not offer them either.
RUNNER_FORBIDDEN_WORD_SAMPLES = (
    "nv show system reboot",
    "nv show system reboot reason",
    "nv show system ztp",
    "nv config find shutdown",
    "sudo vtysh -c 'show running-config | include shutdown'",
    "journalctl --no-pager -n 100 -u ztp",
    "journalctl --no-pager -n 100 -g reboot",
    "journalctl --no-pager -n 50 -g mlxlink",
    "journalctl --no-pager -n 50 -g onie-install",
    'journalctl --no-pager -n 50 -g "nv set"',
    'journalctl --no-pager -n 50 -g "nv unset"',
    'journalctl --no-pager -n 50 -g "nv config apply"',
    # The runner matches these words in any letter case; so must the policy.
    "nv show system REBOOT",
    "nv show system Ztp",
    "nv config find ShutDown",
    "sudo vtysh -c 'show running-config | include SHUTDOWN'",
    "journalctl --no-pager -n 100 -g Reboot",
    "journalctl --no-pager -n 50 -g MLXLINK",
    "journalctl --no-pager -n 50 -g ONIE-Install",
    'journalctl --no-pager -n 50 -g "NV SET"',
    'journalctl --no-pager -n 50 -g "Nv Unset"',
    'journalctl --no-pager -n 50 -g "NV Config Apply"',
)

# The fallback text of _policy_block_hint (html/ai-api.sh) reaches the model
# after a blocked command. Every family it names, with the commands it stands
# for: a family the policy does not allow must not be advertised.
BLOCK_HINT_FAMILIES = {
    "nv show ...": ("nv show interface", "nv show vrf default router bgp neighbor"),
    "nv config show|diff|find": ("nv config show", "nv config diff", "nv config find bgp"),
    "sudo vtysh -c 'show ...'": ("sudo vtysh -c 'show bgp summary'",),
    "ip [-d] link|addr|route|neigh show": (
        "ip link show", "ip addr show", "ip route show", "ip neigh show",
        "ip -d link show", "ip -d addr show", "ip -d route show", "ip -d neigh show",
    ),
    "bridge fdb|vlan show": ("bridge fdb show", "bridge vlan show"),
    "ethtool -m|-S|-i|--show-fec <port>": (
        "ethtool -m swp1", "ethtool -S swp1", "ethtool -i swp1",
        "ethtool --show-fec swp1",
    ),
    "cat /sys/class/net/<port>/mtu": ("cat /sys/class/net/swp1/mtu",),
    "lldpctl": ("lldpctl",),
    "clagctl": ("clagctl",),
    "journalctl --no-pager -n 200": ("journalctl --no-pager -n 200",),
    "dmesg": ("dmesg",),
    "uptime": ("uptime",),
    "free": ("free",),
    "df": ("df",),
}


class AiPolicyAndRunnerAgreeTests(unittest.TestCase):
    def assert_no_disagreement(self, commands):
        commands = list(commands)
        generic = runner_verdicts(commands, "")
        composed = runner_verdicts(commands, "ai-readonly")
        for command in commands:
            with self.subTest(command=command):
                allowed, reason = validate_ai_readonly_command(command)
                if not allowed:
                    self.assertIsNotNone(
                        composed[command],
                        "policy rejects (%s) but the Ask-AI path runs it" % reason,
                    )
                    continue
                self.assertIsNone(
                    generic[command],
                    "allowed by the Ask-AI policy, rejected by the runner",
                )
                self.assertIsNone(composed[command])

    def test_representative_policy_commands_pass_the_runner(self):
        for command in REPRESENTATIVE:
            allowed, reason = validate_ai_readonly_command(command)
            self.assertTrue(
                allowed,
                "%r left the policy (%s); move it out of REPRESENTATIVE"
                % (command, reason),
            )
        self.assert_no_disagreement(REPRESENTATIVE)

    def test_commands_the_policy_tests_allow_pass_the_runner(self):
        commands = commands_the_policy_tests_expect_allowed()
        self.assertGreaterEqual(len(commands), 13)
        self.assert_no_disagreement(commands)

    def test_kb_runbook_forms_run_through_both_layers(self):
        composed = runner_verdicts(KB_RUNBOOK_FORMS, "ai-readonly")
        for command in KB_RUNBOOK_FORMS:
            with self.subTest(command=command):
                self.assertIsNone(composed[command])

    def test_block_hint_names_only_commands_both_layers_accept(self):
        hint = load_symbols("_policy_block_hint")["_policy_block_hint"](
            "tcpdump -i swp1", "command is not in the Ask-AI read-only policy"
        )
        prefix = "allowed read-only families: "
        self.assertTrue(hint.startswith(prefix), hint)
        self.assertEqual(hint[len(prefix):].split(", "), list(BLOCK_HINT_FAMILIES))
        commands = [
            command for family in BLOCK_HINT_FAMILIES.values() for command in family
        ]
        # The runbook forms are the ones a blocked model most needs to be told.
        self.assertLessEqual(
            {"ethtool --show-fec swp1", "ip -d link show", "cat /sys/class/net/swp1/mtu"},
            set(commands),
        )
        for command in commands:
            allowed, reason = validate_ai_readonly_command(command)
            self.assertTrue(allowed, "%r is named by the hint: %s" % (command, reason))
        self.assert_no_disagreement(commands)

    def test_words_the_runner_forbids_are_not_offered_by_the_policy(self):
        start = FABRIC_API.index("FORBIDDEN_PATTERNS = [", _START)
        end = FABRIC_API.index("\n]", start) + 2
        runner_patterns = ast.literal_eval(
            FABRIC_API[start:end].split("=", 1)[1].strip()
        )
        self.assertEqual(
            tuple(runner_patterns), ai_command_policy._RUNNER_FORBIDDEN_PATTERNS
        )
        generic = runner_verdicts(RUNNER_FORBIDDEN_WORD_SAMPLES, "")
        for command in RUNNER_FORBIDDEN_WORD_SAMPLES:
            with self.subTest(command=command):
                self.assertIsNotNone(generic[command])
                allowed, reason = validate_ai_readonly_command(command)
                self.assertFalse(allowed)
                self.assertIn("not allowed by the device command runner", reason)
        self.assert_no_disagreement(RUNNER_FORBIDDEN_WORD_SAMPLES)


class RunnerStaysReadOnlyTests(unittest.TestCase):
    """The forms added to the generic whitelist must not admit a write."""

    def test_new_forms_do_not_authorize_mutations(self):
        commands = (
            "ip -d",
            "ip -d link set swp1 down",
            "ip -d route flush 10.0.0.0/8",
            "ip -d addr add 10.0.0.1/32 dev lo",
            "ip -details link show",
            "ip -d -batch /tmp/commands",
            "ethtool --set-fec swp1 encoding rs",
            "ethtool --show-fec swp1 swp2",
            "ethtool --show-fec swp1 encoding rs",
            "ethtool -s swp1 speed 100",
            "cat /sys/class/net/swp1/address",
            "cat /sys/class/net/../mtu",
            "cat /sys/class/net/.hidden/mtu",
            "cat /sys/class/net/swp1/../../../etc/passwd",
            "cat /sys/class/net/swp1/mtu /etc/passwd",
            "tail -f /sys/class/net/swp1/mtu",
            "sudo vtysh -c 'show ip route | include ^B | include x'",
            "sudo vtysh -c 'configure terminal | include ^B'",
        )
        generic = runner_verdicts(commands, "")
        for command in commands:
            with self.subTest(command=command):
                self.assertIsNotNone(generic[command])

    def test_shell_composition_is_still_rejected_by_the_runner(self):
        commands = (
            "ethtool --show-fec swp1; reboot",
            "ip -d link show swp1 && ip link set swp1 down",
            "cat /sys/class/net/swp1/mtu > /tmp/x",
            "cat /sys/class/net/swp1/mtu | tee /tmp/x",
            "cat /sys/class/net/$(hostname)/mtu",
        )
        generic = runner_verdicts(commands, "")
        for command in commands:
            with self.subTest(command=command):
                self.assertIsNotNone(generic[command])


if __name__ == "__main__":
    unittest.main()
