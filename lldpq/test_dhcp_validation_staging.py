#!/usr/bin/env python3
"""Checks that saving the Provision inventory can still validate DHCP.

Every inventory save syntax-checks the reservations it is about to write, and
that check stages a candidate *inside* the live DHCP directory on purpose:
dhcpd is AppArmor-confined on Debian/Ubuntu and may not read /tmp, so a
candidate parked there is refused on permissions before its syntax is judged.
/etc/dhcp is root-owned and the CGI runs as www-data, so the staging write
escalates to `sudo tee`.

The staged name used to carry the CGI's process id, which no sudoers rule can
name without a wildcard.  sudo refused the write, and every save from the web
UI died with "Save failed: Could not stage a DHCP candidate for validation",
whatever the operator had changed.  The names are fixed now and granted
verbatim in /etc/sudoers.d/www-data-provision.

These tests hold the two sides together — the paths the API stages to and the
paths the installer grants — and cover what a shared, fixed name introduces:
serialised access, and a refusal message an operator can act on.

The fake `sudo` below stands in for the real one plus its policy file: it
consults the grant the installer actually writes, and emulates root's ability
to write into a directory that denies the calling user.
"""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import re
import stat
import tempfile
import textwrap
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = (ROOT / "install.sh").read_text(encoding="utf-8")
DOCKERFILE = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
PROVISION_API = (ROOT / "html" / "provision-api.sh").read_text(encoding="utf-8")
_BODY = PROVISION_API[
    PROVISION_API.index("python3 << 'PYTHON_SCRIPT'\n"):
    PROVISION_API.rindex("\nPYTHON_SCRIPT\n")
]
_TREE = ast.parse(_BODY)

PROVISION_SUDOERS = "/etc/sudoers.d/www-data-provision"
# The directory the API stages into on a real host, and the one the installer
# names in its grant.  Tests retarget it at a temporary directory.
LIVE_DHCP_DIR = "/etc/dhcp"

FUNCTIONS = (
    "_stage_validation_file",
    "_discard_validation_file",
    "dhcp_validation_lock",
    "validate_dhcp_config_candidate",
    "validate_dhcp_hosts_candidate",
)


def extract_function(name: str) -> str:
    """Slice one top-level def out of the CGI's embedded Python by its span.

    A decorated def reports the `def` line, so @contextmanager would be lost.
    """
    for node in _TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            start = min([node.lineno] +
                        [decorator.lineno for decorator in node.decorator_list])
            lines = _BODY.splitlines()[start - 1:node.end_lineno]
            return "\n".join(lines) + "\n"
    raise AssertionError(f"{name}() not found in provision-api.sh")


def extract_constant(name: str):
    """Read one module-level literal, so the test never restates the source."""
    for node in _TREE.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found in provision-api.sh")


STAGED_CONF_NAME = extract_constant("DHCP_VALIDATION_CONF_NAME")
STAGED_HOSTS_NAME = extract_constant("DHCP_VALIDATION_HOSTS_NAME")
LOCK_WAIT_SECONDS = extract_constant("DHCP_VALIDATION_LOCK_WAIT_SECONDS")


def granted_root_commands(text: str, sudoers_file: str) -> list[str]:
    """Every command one www-data policy grants, as the shell writes it."""
    policies = [
        match.group(1)
        for match in re.finditer(
            r'echo "www-data ALL=\(root\) NOPASSWD:\s*([^"]+)"', text
        )
        if sudoers_file in text[match.end():match.end() + 120]
    ]
    if len(policies) != 1:
        raise AssertionError(
            f"expected exactly one {sudoers_file} policy, found {len(policies)}"
        )
    return [command.strip() for command in policies[0].split(",")]


def load_api(lock_path: Path):
    """Exec just the validation helpers, isolated from the CGI dispatcher."""
    import contextlib
    import fcntl
    import shutil
    import subprocess
    import time

    namespace = {
        "os": os, "re": re, "subprocess": subprocess, "shutil": shutil,
        "fcntl": fcntl, "time": time, "contextmanager": contextlib.contextmanager,
        "DHCP_VALIDATION_CONF_NAME": STAGED_CONF_NAME,
        "DHCP_VALIDATION_HOSTS_NAME": STAGED_HOSTS_NAME,
        "DHCP_VALIDATION_LOCK_FILE": str(lock_path),
        "DHCP_VALIDATION_LOCK_WAIT_SECONDS": LOCK_WAIT_SECONDS,
    }
    for name in FUNCTIONS:
        exec(compile(extract_function(name), "provision-api.sh", "exec"), namespace)
    return namespace


class SudoersGrantContractTest(unittest.TestCase):
    """The installer's grant and the API's staged paths must never drift."""

    def test_installer_grants_the_exact_paths_the_api_stages(self):
        granted = granted_root_commands(INSTALL_SH, PROVISION_SUDOERS)
        for name in (STAGED_CONF_NAME, STAGED_HOSTS_NAME):
            self.assertIn(f"/usr/bin/tee {LIVE_DHCP_DIR}/{name}", granted)

    def test_docker_image_grants_the_same_validation_paths(self):
        granted = granted_root_commands(DOCKERFILE, PROVISION_SUDOERS)
        for name in (STAGED_CONF_NAME, STAGED_HOSTS_NAME):
            self.assertIn(f"/usr/bin/tee {LIVE_DHCP_DIR}/{name}", granted)

    def test_the_tee_grant_never_becomes_a_wildcard(self):
        """A fixed name is the whole reason the grant can stay this narrow."""
        for text in (INSTALL_SH, DOCKERFILE):
            for command in granted_root_commands(text, PROVISION_SUDOERS):
                if command.startswith("/usr/bin/tee"):
                    self.assertNotIn("*", command)
                    self.assertEqual(len(command.split()), 2, command)

    def test_the_staged_names_are_no_longer_derived_from_the_pid(self):
        source = extract_function("validate_dhcp_config_candidate")
        self.assertNotIn("getpid", source)
        self.assertIn("DHCP_VALIDATION_CONF_NAME", source)
        self.assertIn("DHCP_VALIDATION_HOSTS_NAME", source)

    def test_validation_does_not_reuse_the_dhcp_operation_lock(self):
        """A save already holds the operation lock while it validates, and
        flock refuses a second descriptor on the same file."""
        source = extract_function("validate_dhcp_config_candidate")
        self.assertIn("with dhcp_validation_lock():", source)
        self.assertNotIn("dhcp_operation_lock", source)

    def test_discarding_a_candidate_stays_within_the_granted_commands(self):
        granted = granted_root_commands(INSTALL_SH, PROVISION_SUDOERS)
        self.assertIn("/usr/bin/rm", granted)
        self.assertIn("/usr/bin/chmod", granted)


class DhcpValidationStagingTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.conf_dir = self.root / "etc" / "dhcp"
        self.conf_dir.mkdir(parents=True)
        self.conf = self.conf_dir / "dhcpd.conf"
        self.hosts = self.conf_dir / "dhcpd.hosts"
        self.conf.write_text(self.live_conf(), encoding="utf-8")
        self.hosts.write_text("# live reservations\n", encoding="utf-8")

        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "state"
        self.state.mkdir()
        self.seen = self.state / "dhcpd-was-given"
        self.body = self.state / "dhcpd-read"
        self.order = self.state / "dhcpd-order"
        self.sudo_log = self.state / "sudo-calls"
        self.allowlist = self.state / "sudoers-policy"

        self.install_dhcpd()
        self.install_sudo(self.installer_grant())
        environment = mock.patch.dict(os.environ, {
            "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}",
            "DHCP_CONF_FILE": str(self.conf),
        })
        environment.start()
        self.addCleanup(environment.stop)
        self.api = load_api(self.root / "dhcp-validate.lock")

    # ---------- fixtures ----------
    def live_conf(self, marker: str = "# live") -> str:
        return (
            f"{marker}\n"
            "subnet 192.168.100.0 netmask 255.255.255.0 {\n"
            "  range 192.168.100.210 192.168.100.249;\n"
            "}\n"
            f'include "{self.hosts}";\n'
        )

    def staged_conf(self) -> Path:
        return self.conf_dir / STAGED_CONF_NAME

    def staged_hosts(self) -> Path:
        return self.conf_dir / STAGED_HOSTS_NAME

    def leftovers(self) -> list[str]:
        return sorted(entry.name for entry in self.conf_dir.iterdir()
                      if entry.name.startswith("."))

    def write_tool(self, name: str, script: str) -> Path:
        path = self.bin / name
        path.write_text("#!/bin/bash\n" + textwrap.dedent(script), encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
        return path

    def install_dhcpd(self, verdict: str = "exit 0", delay: str = "") -> None:
        """A validator confined to the DHCP directory, like AppArmor's."""
        self.write_tool("dhcpd", f"""
            conf=""
            while [ $# -gt 0 ]; do
                case "$1" in
                    -cf) conf="$2"; shift 2 ;;
                    *) shift ;;
                esac
            done
            check_readable() {{
                case "$1" in
                    '{self.conf_dir}'/*) return 0 ;;
                esac
                echo "Can't open $1: Permission denied" >&2
                exit 1
            }}
            check_readable "$conf"
            printf '%s\\n' "$conf" >> '{self.seen}'
            printf 'start %s\\n' "$(head -n 1 "$conf")" >> '{self.order}'
            cat "$conf" >> '{self.body}'
            while IFS= read -r line; do
                case "$line" in
                    include*)
                        inc=$(printf '%s' "$line" | sed 's/.*include *"//; s/".*//')
                        check_readable "$inc"
                        ;;
                esac
            done < "$conf"
            {delay}
            printf 'end %s\\n' "$(head -n 1 "$conf")" >> '{self.order}'
            {verdict}
        """)

    def installer_grant(self) -> list[str]:
        """install.sh's real policy, retargeted at this test's DHCP directory."""
        return [command.replace(LIVE_DHCP_DIR, str(self.conf_dir))
                for command in granted_root_commands(INSTALL_SH, PROVISION_SUDOERS)]

    def grant_without_validation_paths(self) -> list[str]:
        """What an installation predating the fix still has on disk."""
        return [command for command in self.installer_grant()
                if STAGED_CONF_NAME not in command
                and STAGED_HOSTS_NAME not in command]

    def install_sudo(self, allowlist: list[str]) -> None:
        self.allowlist.write_text("\n".join(allowlist) + "\n", encoding="utf-8")
        # Root's write into a directory that denies the caller is emulated by
        # lifting the owner write bit for exactly the granted command.
        self.write_tool("sudo", f"""
            printf '%s\\n' "$*" >> '{self.sudo_log}'
            name="$1"; shift
            full="/usr/bin/$name $*"
            permitted=1
            while IFS= read -r entry; do
                [ -n "$entry" ] || continue
                if [ "$entry" = "$full" ] || [ "$entry" = "/usr/bin/$name" ]; then
                    permitted=0
                    break
                fi
            done < '{self.allowlist}'
            if [ "$permitted" -ne 0 ]; then
                echo "Sorry, user www-data is not allowed to execute '$full' as root." >&2
                exit 1
            fi
            case "$name" in
                tee) target="$1" ;;
                chmod|rm) target="$2" ;;
                *) target="" ;;
            esac
            restore=""
            if [ -n "$target" ]; then
                directory=$(dirname "$target")
                if [ ! -w "$directory" ]; then
                    chmod u+w "$directory"
                    restore=1
                fi
            fi
            "$name" "$@" > /dev/null
            status=$?
            [ -n "$restore" ] && chmod u-w "$directory"
            exit $status
        """)

    def make_directory_root_owned(self) -> None:
        """Deny the CGI user the direct write, exactly as /etc/dhcp does."""
        self.conf_dir.chmod(0o555)
        self.addCleanup(self.conf_dir.chmod, 0o755)

    def sudo_calls(self) -> list[str]:
        if not self.sudo_log.exists():
            return []
        return self.sudo_log.read_text(encoding="utf-8").splitlines()

    def validate(self, conf_text=None, hosts_text="# candidate\n"):
        return self.api["validate_dhcp_config_candidate"](
            self.live_conf() if conf_text is None else conf_text,
            hosts_text, str(self.hosts),
        )

    # ---------- the ordinary path ----------
    def test_a_writable_dhcp_directory_never_calls_sudo(self):
        self.validate()
        self.assertEqual(self.sudo_calls(), [])

    def test_validation_reads_the_staged_candidate_not_the_live_config(self):
        self.validate(hosts_text="host leaf01 { fixed-address 192.168.100.11; }\n")
        self.assertEqual(self.seen.read_text(encoding="utf-8").split(),
                         [str(self.staged_conf())])
        read_back = self.body.read_text(encoding="utf-8")
        self.assertIn(f'include "{self.staged_hosts()}";', read_back)
        self.assertNotIn(f'include "{self.hosts}";', read_back)

    def test_the_live_config_and_hosts_are_never_modified(self):
        self.validate(hosts_text="host leaf01 { fixed-address 192.168.100.11; }\n")
        self.assertEqual(self.conf.read_text(encoding="utf-8"), self.live_conf())
        self.assertEqual(self.hosts.read_text(encoding="utf-8"),
                         "# live reservations\n")

    def test_nothing_is_left_behind_in_the_dhcp_directory(self):
        self.validate()
        self.assertEqual(self.leftovers(), [])

    def test_a_config_without_the_managed_include_is_rejected(self):
        with self.assertRaises(RuntimeError) as caught:
            self.validate(conf_text="subnet 192.168.100.0 netmask 255.255.255.0 {}\n")
        self.assertIn("does not include the managed hosts file", str(caught.exception))
        self.assertEqual(self.leftovers(), [])

    # ---------- the reported failure ----------
    def test_a_root_owned_directory_stages_through_the_granted_tee(self):
        self.make_directory_root_owned()
        self.validate()
        self.assertTrue(any(call.startswith("tee ") for call in self.sudo_calls()))
        self.assertEqual(self.leftovers(), [])

    def test_a_host_without_the_grant_is_told_what_to_add(self):
        """The old message named no path, no file and no remedy."""
        self.install_sudo(self.grant_without_validation_paths())
        self.make_directory_root_owned()
        with self.assertRaises(RuntimeError) as caught:
            self.validate()
        message = str(caught.exception)
        self.assertIn(str(self.staged_hosts()), message)
        self.assertIn(PROVISION_SUDOERS, message)
        self.assertIn("Re-run install.sh", message)
        self.assertIn("not allowed to execute", message)
        self.assertNotEqual(
            message, "Could not stage a DHCP candidate for validation")

    def test_the_inventory_save_path_reports_the_same_remedy(self):
        """This is the endpoint the operator's failed save went through."""
        self.install_sudo(self.grant_without_validation_paths())
        self.make_directory_root_owned()
        with self.assertRaises(RuntimeError) as caught:
            self.api["validate_dhcp_hosts_candidate"](
                "host leaf01 { fixed-address 192.168.100.11; }\n", str(self.hosts))
        self.assertIn(PROVISION_SUDOERS, str(caught.exception))

    # ---------- a real syntax error must still stop the save ----------
    def test_a_genuine_syntax_error_is_reported_in_dhcpds_own_words(self):
        self.install_dhcpd(verdict=textwrap.dedent("""
            echo "$conf line 42: semicolon expected." >&2
            echo "Configuration file errors encountered -- exiting" >&2
            exit 1
        """))
        with self.assertRaises(RuntimeError) as caught:
            self.validate()
        message = str(caught.exception)
        self.assertIn("DHCP validation failed", message)
        self.assertIn("semicolon expected", message)
        # The candidate's own path would only confuse the operator.
        self.assertIn("dhcpd.conf (candidate)", message)
        self.assertNotIn(str(self.staged_conf()), message)

    def test_a_failed_validation_also_leaves_nothing_behind(self):
        self.install_dhcpd(verdict='echo "$conf line 1: bad." >&2; exit 1')
        with self.assertRaises(RuntimeError):
            self.validate()
        self.assertEqual(self.leftovers(), [])
        self.assertEqual(self.conf.read_text(encoding="utf-8"), self.live_conf())

    # ---------- the shared name has to be serialised ----------
    def test_a_second_validation_never_touches_a_candidate_it_does_not_own(self):
        import fcntl

        self.api["DHCP_VALIDATION_LOCK_WAIT_SECONDS"] = 0
        in_flight = "# owned by the other request\n"
        self.staged_conf().write_text(in_flight, encoding="utf-8")
        holder = open(self.root / "dhcp-validate.lock", "a+")
        self.addCleanup(holder.close)
        fcntl.flock(holder.fileno(), fcntl.LOCK_EX)

        with self.assertRaises(RuntimeError) as caught:
            self.validate()

        self.assertIn("Another DHCP validation is already in progress",
                      str(caught.exception))
        self.assertEqual(self.staged_conf().read_text(encoding="utf-8"), in_flight)
        self.assertFalse(self.seen.exists(), "dhcpd ran on a foreign candidate")

    def test_the_lock_is_released_for_the_next_save(self):
        self.validate()
        self.validate()
        self.assertEqual(
            self.seen.read_text(encoding="utf-8").split(),
            [str(self.staged_conf()), str(self.staged_conf())],
        )

    def test_concurrent_validations_are_serialised_not_interleaved(self):
        self.install_dhcpd(delay="sleep 0.4")
        started = threading.Barrier(2)

        def run(marker):
            started.wait(timeout=5)
            self.validate(conf_text=self.live_conf(marker=f"# {marker}"),
                          hosts_text=f"# {marker}\n")
            return marker

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = sorted(pool.map(run, ("first", "second")))

        self.assertEqual(results, ["first", "second"])
        order = self.order.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(order), 4, order)
        # Each run must see its own marker at both ends: an interleaved pair
        # would have read the other request's candidate from the shared name.
        self.assertEqual(order[0].replace("start", "end"), order[1])
        self.assertEqual(order[2].replace("start", "end"), order[3])
        self.assertNotEqual(order[0], order[2])
        self.assertEqual(self.leftovers(), [])


if __name__ == "__main__":
    unittest.main()
