#!/usr/bin/env python3
"""Telemetry enable/disable must not apply someone else's pending NVUE changes.

run-telemetry-commands runs "nv set/unset ... && nv config apply -y" on every
selected switch with the shared device account. "nv config apply" applies the
whole pending revision, so the action first refuses a switch whose pending
revision is not empty or cannot be read, and detaches its own staged change
when the sequence fails so that a retry is not blocked by it.

The action's Python is taken verbatim from html/fabric-api.sh. A stand-in
"sudo" on PATH replaces "sudo -u <user> ssh ... <target> <remote command>": it
records the remote command and runs it through sh against a stand-in "nv".
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FABRIC_API = (ROOT / "html" / "fabric-api.sh").read_text(encoding="utf-8")

_START = FABRIC_API.index("python3 << 'PYTHON_TELEMETRY'\n") + len(
    "python3 << 'PYTHON_TELEMETRY'\n"
)
_END = FABRIC_API.index("\nPYTHON_TELEMETRY\n", _START)
ACTION = FABRIC_API[_START:_END]

ENABLE_COMMANDS = [
    "nv set system telemetry ai-ethernet-stats export state enabled",
    "nv set system telemetry ai-ethernet-stats sample-interval 30",
    "nv set system telemetry export otlp grpc destination 192.0.2.50 port 4317",
    "nv set system telemetry export otlp grpc insecure enabled",
    "nv set system telemetry export otlp state enabled",
    "nv set system telemetry export vrf mgmt",
    "nv set system telemetry interface-stats export state enabled",
    "nv set system telemetry interface-stats sample-interval 30",
    "nv config apply -y",
]
DISABLE_COMMANDS = [
    "nv unset system telemetry ai-ethernet-stats",
    "nv unset system telemetry export",
    "nv unset system telemetry interface-stats",
    "nv config apply -y",
]

PENDING_MESSAGE = (
    "Pending un-applied NVUE changes on this switch, nothing was changed. "
    "Review them with 'nv config diff', then apply or 'nv config detach' them "
    "and retry."
)
UNCHECKED_MESSAGE = (
    "Could not check this switch for pending NVUE changes ('nv config diff' "
    "failed), nothing was changed."
)
GUARD = (
    "d=$(nv config diff); rc=$?; "
    "if [ -n \"$(printf %s \"$d\" | tr -d '[:space:][]{}')\" ]; then "
    'echo "' + PENDING_MESSAGE + '" >&2; exit 3; fi; '
    '[ "$rc" -eq 0 ] || { echo "' + UNCHECKED_MESSAGE + '" >&2; exit 4; }'
)
ON_FAILURE = "{ rc=$?; nv config detach >/dev/null 2>&1; exit $rc; }"


def expected_remote_command(commands):
    return GUARD + "; { " + " && ".join(commands) + "; } || " + ON_FAILURE


SOMEONE_ELSES_CHANGE = textwrap.dedent("""\
    - set:
        interface:
          swp1:
            link:
              state: down
""")

# sudo -u <user> ssh <options> <user@ip> <remote command>
SUDO_STUB = textwrap.dedent("""\
    #!/bin/bash
    args=("$@")
    remote="${args[$(($# - 1))]}"
    target="${args[$(($# - 2))]}"
    device_dir="$STUB_STATE/${target#*@}"
    mkdir -p "$device_dir"
    printf '%s' "$remote" > "$device_dir/remote-command"
    NV_DEVICE_DIR="$device_dir" exec sh -c "$remote"
""")

# Minimal NVUE: "set/unset" stage into the pending revision, "config diff"
# prints it, "config apply" and "config detach" leave it empty. As measured on
# Cumulus Linux 5.18.0, "config diff" exits 1 when it prints a difference and 0
# with no output on a clean switch; a "diff-exit-0" file selects a release that
# exits 0 either way. A "diff-error" file makes "config diff" fail with that
# text on stderr and nothing on stdout; a "diff-warning" file is printed to
# stderr by a "config diff" that succeeds.
NV_STUB = textwrap.dedent("""\
    #!/bin/sh
    dir="$NV_DEVICE_DIR"
    echo "$*" >> "$dir/nv.log"
    if [ -f "$dir/failing-command" ] && [ "$*" = "$(cat "$dir/failing-command")" ]; then
        echo "Error: stand-in nv refused: $*" >&2
        exit 1
    fi
    case "$1 $2" in
        "config diff")
            if [ -f "$dir/diff-error" ]; then
                cat "$dir/diff-error" >&2
                exit 1
            fi
            [ -f "$dir/diff-warning" ] && cat "$dir/diff-warning" >&2
            if [ -f "$dir/pending" ]; then
                cat "$dir/pending"
                if [ -n "$(tr -d '[:space:][]{}' < "$dir/pending")" ] &&
                   [ ! -f "$dir/diff-exit-0" ]; then
                    exit 1
                fi
            fi
            exit 0
            ;;
        "config apply"|"config detach")
            rm -f "$dir/pending"
            echo "stand-in nv: $2 done"
            exit 0
            ;;
    esac
    case "$1" in
        set|unset)
            echo "- $*" >> "$dir/pending"
            exit 0
            ;;
    esac
    echo "stand-in nv: unexpected $*" >&2
    exit 64
""")

DEVICES = {"leaf-01": "192.0.2.11", "leaf-02": "192.0.2.12"}


class TelemetryPendingChangesTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.state = self.root / "devices"
        stubs = self.root / "bin"
        stubs.mkdir()
        for name, body in (("sudo", SUDO_STUB), ("nv", NV_STUB)):
            path = stubs / name
            path.write_text(body, encoding="utf-8")
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.stubs = stubs
        self.conf = self.root / "lldpq.conf"
        self.conf.write_text(
            f"LLDPQ_DIR={self.root}\nLLDPQ_USER=lldpq\nANSIBLE_DIR={self.root}/none\n",
            encoding="utf-8",
        )
        (self.root / "devices.yaml").write_text(
            "defaults:\n  username: cumulus\ndevices:\n"
            + "".join(f'  "{ip}": {name} @leaf\n' for name, ip in DEVICES.items()),
            encoding="utf-8",
        )
        for ip in DEVICES.values():
            (self.state / ip).mkdir(parents=True)
        source = ACTION.replace("'/etc/lldpq.conf'", repr(str(self.conf)))
        self.assertNotEqual(source, ACTION)
        self.source = source

    def device_dir(self, name):
        return self.state / DEVICES[name]

    def nv_log(self, name):
        log = self.device_dir(name) / "nv.log"
        return log.read_text(encoding="utf-8").splitlines() if log.exists() else []

    def run_action(self, devices, commands):
        result = subprocess.run(
            [sys.executable, "-c", self.source],
            env=dict(
                os.environ,
                PATH=f"{self.stubs}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
                STUB_STATE=str(self.state),
                POST_DATA=json.dumps({"devices": devices, "commands": commands}),
            ),
            capture_output=True,
            text=True,
            check=True,
        )
        lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        per_device = {row["device"]: row for row in lines if "device" in row}
        summary = next((row for row in lines if row.get("complete")), None)
        return per_device, summary, lines

    def test_remote_command_is_guard_commands_then_detach_on_failure(self):
        for commands in (ENABLE_COMMANDS, DISABLE_COMMANDS):
            with self.subTest(commands=commands[0]):
                self.run_action(["leaf-01"], commands)
                remote = (self.device_dir("leaf-01") / "remote-command").read_text(
                    encoding="utf-8"
                )
                self.assertEqual(remote, expected_remote_command(commands))

    def test_clean_device_runs_the_commands_in_order(self):
        per_device, summary, _lines = self.run_action(["leaf-01"], ENABLE_COMMANDS)
        self.assertTrue(per_device["leaf-01"]["success"], per_device)
        self.assertEqual(
            self.nv_log("leaf-01"),
            ["config diff"] + [command[len("nv "):] for command in ENABLE_COMMANDS],
        )
        self.assertEqual((summary["success"], summary["failed"]), (1, 0))

    def test_device_with_pending_changes_is_left_untouched(self):
        pending = self.device_dir("leaf-01") / "pending"
        pending.write_text(SOMEONE_ELSES_CHANGE, encoding="utf-8")

        per_device, summary, _lines = self.run_action(
            ["leaf-01", "leaf-02"], ENABLE_COMMANDS
        )

        blocked = per_device["leaf-01"]
        self.assertFalse(blocked["success"])
        self.assertEqual(blocked["error"], PENDING_MESSAGE)
        # Nothing staged, nothing applied, and the other operator's pending
        # revision is neither applied nor detached.
        self.assertEqual(self.nv_log("leaf-01"), ["config diff"])
        self.assertEqual(pending.read_text(encoding="utf-8"), SOMEONE_ELSES_CHANGE)

        self.assertTrue(per_device["leaf-02"]["success"], per_device)
        self.assertIn("config apply -y", self.nv_log("leaf-02"))
        self.assertEqual(
            (summary["total"], summary["success"], summary["failed"]), (2, 1, 1)
        )

    def test_pending_changes_are_named_whatever_status_the_diff_exits_with(self):
        # 5.18.0 exits 1 with a difference; the refusal must still say that
        # changes are pending, not that the switch could not be checked.
        for exits_zero in (False, True):
            with self.subTest(diff_exits_zero=exits_zero):
                device_dir = self.device_dir("leaf-01")
                (device_dir / "nv.log").unlink(missing_ok=True)
                marker = device_dir / "diff-exit-0"
                marker.touch() if exits_zero else marker.unlink(missing_ok=True)
                pending = device_dir / "pending"
                pending.write_text(SOMEONE_ELSES_CHANGE, encoding="utf-8")
                per_device, _summary, _lines = self.run_action(
                    ["leaf-01"], ENABLE_COMMANDS
                )
                self.assertFalse(per_device["leaf-01"]["success"])
                self.assertEqual(per_device["leaf-01"]["error"], PENDING_MESSAGE)
                self.assertEqual(self.nv_log("leaf-01"), ["config diff"])
                self.assertEqual(
                    pending.read_text(encoding="utf-8"), SOMEONE_ELSES_CHANGE
                )

    def test_disable_is_guarded_too(self):
        pending = self.device_dir("leaf-01") / "pending"
        pending.write_text(SOMEONE_ELSES_CHANGE, encoding="utf-8")
        per_device, _summary, _lines = self.run_action(["leaf-01"], DISABLE_COMMANDS)
        self.assertEqual(per_device["leaf-01"]["error"], PENDING_MESSAGE)
        self.assertEqual(self.nv_log("leaf-01"), ["config diff"])

    def test_device_whose_pending_revision_cannot_be_read_is_left_untouched(self):
        # A failing "nv config diff" (nvued busy or restarting) says nothing
        # about the pending revision, so it must not pass for an empty one.
        refused = ENABLE_COMMANDS[5][len("nv "):]
        nvue_error = "Error: stand-in nvued is not answering"
        for diff_error, failing_command in (
            (nvue_error + "\n", None),
            (nvue_error + "\n", refused),
            ("", None),
        ):
            with self.subTest(diff_error=diff_error, failing_command=failing_command):
                device_dir = self.device_dir("leaf-01")
                (device_dir / "nv.log").unlink(missing_ok=True)
                (device_dir / "failing-command").unlink(missing_ok=True)
                pending = device_dir / "pending"
                pending.write_text(SOMEONE_ELSES_CHANGE, encoding="utf-8")
                (device_dir / "diff-error").write_text(diff_error, encoding="utf-8")
                if failing_command:
                    (device_dir / "failing-command").write_text(
                        failing_command, encoding="utf-8"
                    )

                per_device, summary, _lines = self.run_action(
                    ["leaf-01", "leaf-02"], ENABLE_COMMANDS
                )

                blocked = per_device["leaf-01"]
                self.assertFalse(blocked["success"], per_device)
                # NVUE's own reason first, then what LLDPq did about it.
                self.assertEqual(blocked["error"], diff_error + UNCHECKED_MESSAGE)
                # The other operator's pending revision is neither applied
                # (the sequence succeeding) nor detached (a later command
                # failing): nothing ran after the check.
                self.assertEqual(self.nv_log("leaf-01"), ["config diff"])
                self.assertEqual(pending.read_text(encoding="utf-8"), SOMEONE_ELSES_CHANGE)

                self.assertTrue(per_device["leaf-02"]["success"], per_device)
                self.assertEqual(
                    (summary["total"], summary["success"], summary["failed"]), (2, 1, 1)
                )

    def test_stderr_of_a_successful_diff_is_not_taken_for_pending_changes(self):
        device_dir = self.device_dir("leaf-01")
        (device_dir / "diff-warning").write_text(
            "Warning: stand-in nv notice\n", encoding="utf-8"
        )
        per_device, _summary, _lines = self.run_action(["leaf-01"], DISABLE_COMMANDS)
        self.assertTrue(per_device["leaf-01"]["success"], per_device)
        self.assertIn("config apply -y", self.nv_log("leaf-01"))

    def test_empty_diff_renderings_do_not_block(self):
        for rendering in ("", "\n", "  \n\n", "[]\n", "{}\n"):
            with self.subTest(rendering=rendering):
                device_dir = self.device_dir("leaf-01")
                (device_dir / "nv.log").unlink(missing_ok=True)
                (device_dir / "pending").write_text(rendering, encoding="utf-8")
                per_device, _summary, _lines = self.run_action(
                    ["leaf-01"], DISABLE_COMMANDS
                )
                self.assertTrue(per_device["leaf-01"]["success"], per_device)
                self.assertIn("config apply -y", self.nv_log("leaf-01"))

    def test_failed_apply_detaches_own_change_so_a_retry_is_not_blocked(self):
        device_dir = self.device_dir("leaf-01")
        (device_dir / "failing-command").write_text("config apply -y", encoding="utf-8")

        per_device, _summary, _lines = self.run_action(["leaf-01"], ENABLE_COMMANDS)

        failed = per_device["leaf-01"]
        self.assertFalse(failed["success"])
        # The operator still sees why NVUE refused, not the clean-up.
        self.assertEqual(failed["error"], "Error: stand-in nv refused: config apply -y")
        self.assertEqual(self.nv_log("leaf-01")[-2:], ["config apply -y", "config detach"])
        self.assertFalse((device_dir / "pending").exists())

        (device_dir / "failing-command").unlink()
        (device_dir / "nv.log").unlink()
        per_device, _summary, _lines = self.run_action(["leaf-01"], ENABLE_COMMANDS)
        self.assertTrue(per_device["leaf-01"]["success"], per_device)

    def test_failed_set_detaches_and_never_applies(self):
        device_dir = self.device_dir("leaf-01")
        refused = ENABLE_COMMANDS[5][len("nv "):]
        (device_dir / "failing-command").write_text(refused, encoding="utf-8")

        per_device, _summary, _lines = self.run_action(["leaf-01"], ENABLE_COMMANDS)

        self.assertFalse(per_device["leaf-01"]["success"])
        self.assertEqual(
            per_device["leaf-01"]["error"], f"Error: stand-in nv refused: {refused}"
        )
        log = self.nv_log("leaf-01")
        self.assertEqual(log[-2:], [refused, "config detach"])
        self.assertNotIn("config apply -y", log)
        self.assertFalse((device_dir / "pending").exists())

    def test_clients_cannot_send_the_guard_commands_themselves(self):
        for command in ("nv config detach", "nv config diff"):
            with self.subTest(command=command):
                _per_device, _summary, lines = self.run_action(["leaf-01"], [command])
                self.assertEqual(
                    lines,
                    [{"success": False, "error": f"Only telemetry commands allowed: {command}"}],
                )
        self.assertEqual(self.nv_log("leaf-01"), [])


if __name__ == "__main__":
    unittest.main()
