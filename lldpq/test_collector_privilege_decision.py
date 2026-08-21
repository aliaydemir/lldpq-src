#!/usr/bin/env python3
"""Checks the collectors publish without asking for privilege they do not need.

The web UI's "Run LLDP Check" button failed forever on a customer deployment:

    LLDP refresh failed with status 1; automatic retry in 300s
    Automatic retry is scheduled (attempt 261)

`./assets.sh` and `./check-lldp.sh` succeeded when the operator ran them by hand,
and nothing anywhere recorded a reason. Three defects combined:

1. Every local publication site called bare, unconditional `sudo` - not "escalate
   if the write would fail", just `sudo mktemp`, `sudo cp`, `sudo python3`. Run by
   hand that works off the operator's cached sudo timestamp. The web trigger runs
   from cron as $LLDPQ_USER, where there is no tty and no cached credential, so
   sudo failed immediately and the publication returned 1.

2. Nothing proved at install time that $LLDPQ_USER could write $WEB_ROOT, which is
   the only reason those commands would ever have needed privilege. The collectors
   stage temporary siblings directly inside $WEB_ROOT (`mktemp -d
   "$WEB_ROOT/.monitor-results.new.XXXXXXXXXX"`, and publish_web_file's sibling of
   $WEB_ROOT/lldp_results.ini), so directory write is the actual requirement.

3. `bin/lldpq-trigger` sent both collector streams to /dev/null, so 21 hours of
   identical failures produced nothing but an exit status - not in the UI, not in
   journald.

These tests pin the fix: $WEB_ROOT is owned by the shared collector/web identity,
each converted script takes exactly one privilege decision, every escalation is
non-interactive `sudo -n`, the `sudo` calls that run on remote switches over SSH
are untouched, the publication transaction's ordering and rollback are unchanged,
the installer proves the collector account can write $WEB_ROOT, and the trigger
keeps the reason instead of discarding it.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]

CONFIG_HELPER = ROOT / "bin" / "lldpq-config"
TRIGGER_PATH = ROOT / "bin" / "lldpq-trigger"


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


INSTALL = _read("install.sh")
UNINSTALL = _read("uninstall.sh")
ENTRYPOINT = _read("docker/docker-entrypoint.sh")
TRIGGER = _read("bin/lldpq-trigger")
WRAPPER = _read("bin/lldpq")
CHECK_LLDP = _read("lldpq/check-lldp.sh")
MONITOR = _read("lldpq/monitor.sh")
GET_CONFIGS = _read("lldpq/get-configs.sh")
FABRIC_SCAN_CRON = _read("lldpq/fabric-scan-cron.sh")
TRANSCEIVER = _read("lldpq/collect-transceiver-fw.sh")
ASSETS = _read("lldpq/assets.sh")
VALIDATE = _read("lldpq/lldp-validate.py")

SOURCES = {
    "install.sh": INSTALL,
    "docker/docker-entrypoint.sh": ENTRYPOINT,
    "bin/lldpq": WRAPPER,
    "bin/lldpq-trigger": TRIGGER,
    "lldpq/check-lldp.sh": CHECK_LLDP,
    "lldpq/monitor.sh": MONITOR,
    "lldpq/get-configs.sh": GET_CONFIGS,
    "lldpq/fabric-scan-cron.sh": FABRIC_SCAN_CRON,
    "lldpq/lldp-validate.py": VALIDATE,
}


def _require(needle: str, haystack: str, label: str) -> int:
    """Locate a marker, reporting one line rather than dumping the file.

    monitor.sh and install.sh are hundreds of KB; a plain assertIn buries the
    real message in the whole script.
    """
    index = haystack.find(needle)
    if index < 0:
        raise AssertionError(f"{label} no longer contains: {needle!r}")
    return index


def _count(needle: str, haystack: str) -> int:
    return haystack.count(needle)


def _summarize(offenders: list[str], limit: int = 4) -> str:
    """Report a few examples and a total, never a list long enough to scroll."""
    shown = " | ".join(offenders[:limit])
    if len(offenders) > limit:
        shown += f" | ... and {len(offenders) - limit} more"
    return shown


# --------------------------------------------------------------------------
# Local vs remote: the only `sudo` allowed to stay bare is the switch's own,
# invoked inside an SSH payload. Cut those payloads out before auditing.
# --------------------------------------------------------------------------
REMOTE_PAYLOADS = {
    "lldpq/check-lldp.sh": (
        'if timeout 180 ssh -o ConnectTimeout="$connect_timeout"',
        '\n    " > "$temporary_file"',
    ),
    "lldpq/monitor.sh": (
        'timeout "$ssh_umbrella_timeout" ssh -o ConnectTimeout="$connect_timeout"',
        '\n    \' > "$raw_file" 2>"$ssh_error_file"',
    ),
    "lldpq/collect-transceiver-fw.sh": ("<<'REMOTE_SCRIPT'", "\nREMOTE_SCRIPT\n"),
}


def _split_remote(relative: str, text: str) -> tuple[str, str]:
    """Return (local, remote) halves for a collector that ships a remote payload."""
    opener, closer = REMOTE_PAYLOADS[relative]
    start = _require(opener, text, relative)
    end = _require(closer, text[start:], f"{relative} remote payload terminator")
    return text[:start] + text[start + end:], text[start : start + end]


LOCAL_TEXT = {
    "bin/lldpq": WRAPPER,
    "bin/lldpq-trigger": TRIGGER,
    "lldpq/fabric-scan-cron.sh": FABRIC_SCAN_CRON,
    "lldpq/get-configs.sh": GET_CONFIGS,
    "lldpq/lldp-validate.py": VALIDATE,
}
REMOTE_TEXT = {}
for _relative, _text in (
    ("lldpq/check-lldp.sh", CHECK_LLDP),
    ("lldpq/monitor.sh", MONITOR),
    ("lldpq/collect-transceiver-fw.sh", TRANSCEIVER),
):
    LOCAL_TEXT[_relative], REMOTE_TEXT[_relative] = _split_remote(_relative, _text)


_QUOTED = re.compile(r'"[^"\n]*"|\'[^\'\n]*\'')
_DOCSTRING = re.compile(r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'')
# `sudo` in command position: line start, or after whitespace, `(`, `!`, `$(`.
_SUDO_COMMAND = re.compile(r"(?:(?<=^)|(?<=[\s(!]))sudo(?=\s)")
# `command -v sudo >/dev/null` names sudo, it does not run it.
_NOT_AN_INVOCATION = ("<", ">", "|", "&", ";", ")")


def _strip_comment(line: str) -> str:
    index = 0
    while True:
        index = line.find("#", index)
        if index < 0:
            return line
        if index == 0 or line[index - 1] in " \t":
            return line[:index]
        index += 1


def _interactive_sudo_lines(text: str) -> list[str]:
    """Lines invoking `sudo` as a command without the non-interactive flag.

    Docstrings, string literals and comments are scrubbed first, so prose about
    sudo and `[[ "$LLDPQ_PRIV_MODE" == "sudo" ]]` are not miscounted.
    """
    # Blanked rather than removed, so reported line numbers still match the file.
    blanked = _DOCSTRING.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    offenders = []
    for number, line in enumerate(blanked.split("\n"), start=1):
        if "sudo" not in line or line.lstrip().startswith("#"):
            continue
        scrubbed = _strip_comment(_QUOTED.sub(" ", line))
        for match in _SUDO_COMMAND.finditer(scrubbed):
            following = scrubbed[match.end() :].lstrip()
            if following.startswith("-n"):
                continue
            if following[:1] in _NOT_AN_INVOCATION:
                continue
            if scrubbed[: match.start()].rstrip().endswith("-v"):
                continue
            offenders.append(f"{number}: {line.strip()}")
            break
    return offenders


class WebRootOwnershipTests(unittest.TestCase):
    """$WEB_ROOT itself must carry the shared owner, not only its children."""

    OWN = 'sudo install -d -o "$LLDPQ_USER" -g www-data -m 775 "$WEB_ROOT"'

    def test_install_sh_stays_valid_shell(self) -> None:
        subprocess.run(["bash", "-n", str(ROOT / "install.sh")], check=True)

    def test_the_web_root_itself_is_given_the_shared_owner_and_mode(self) -> None:
        self.assertEqual(
            _count(self.OWN + "\n", INSTALL),
            1,
            "install.sh no longer claims $WEB_ROOT itself as $LLDPQ_USER:www-data 775",
        )

    def test_ownership_is_claimed_before_the_recursive_pass(self) -> None:
        own = _require(self.OWN, INSTALL, "install.sh")
        recursive = _require(
            'sudo chown -R "$LLDPQ_USER:www-data" "$WEB_ROOT/"', INSTALL, "install.sh"
        )
        self.assertLess(own, recursive, "the web root must exist before it is walked")

    def test_the_managed_children_still_get_the_same_treatment(self) -> None:
        for child in ("hstr", "configs", "monitor-results", "topology"):
            with self.subTest(child=child):
                _require(f'"$WEB_ROOT/{child}"', INSTALL, "install.sh")

    def test_the_container_applies_the_same_ownership_to_its_web_root(self) -> None:
        needle = "install -d -o lldpq -g www-data -m 775 /var/www/html\n"
        self.assertEqual(
            _count(needle, ENTRYPOINT),
            1,
            "docker-entrypoint.sh no longer claims /var/www/html itself",
        )
        claim = _require(needle, ENTRYPOINT, "docker-entrypoint.sh")
        children = _require("/var/www/html/hstr", ENTRYPOINT, "docker-entrypoint.sh")
        self.assertLess(claim, children)

    def test_nothing_still_demands_a_root_owned_web_root(self) -> None:
        """uninstall.sh is the only place that asserts web-root ownership."""
        _require(
            "allowed_uids = {0, runtime_user.pw_uid}", UNINSTALL, "uninstall.sh"
        )
        _require(
            "web root failed its ownership/type check", UNINSTALL, "uninstall.sh"
        )


class InstallWriteProbeTests(unittest.TestCase):
    """The install must prove the collector account can publish, not assume it."""

    PROBE = '_web_root_probe="$WEB_ROOT/.lldpq-collector-write-probe"'

    def test_the_probe_exists(self) -> None:
        _require(self.PROBE, INSTALL, "install.sh")

    def test_the_probe_runs_as_the_collector_account(self) -> None:
        _require(
            'sudo -u "$LLDPQ_USER" touch "$_web_root_probe"', INSTALL, "install.sh"
        )

    def test_removal_is_proven_too_not_only_creation(self) -> None:
        """Rollback and archive pruning delete files in $WEB_ROOT."""
        _require(
            'sudo -u "$LLDPQ_USER" rm -f "$_web_root_probe"', INSTALL, "install.sh"
        )

    def test_a_failed_create_probe_stops_the_installer(self) -> None:
        start = _require(
            'if ! sudo -u "$LLDPQ_USER" touch "$_web_root_probe"',
            INSTALL,
            "install.sh",
        )
        tail = INSTALL[start:]
        block = tail[: _require("fi\n", tail, "the web-root create probe") + 3]
        self.assertIn("exit 1", block)

    def test_a_failed_remove_probe_stops_the_installer(self) -> None:
        start = _require(
            'if ! sudo -u "$LLDPQ_USER" rm -f "$_web_root_probe"',
            INSTALL,
            "install.sh",
        )
        tail = INSTALL[start:]
        block = tail[: _require("fi\n", tail, "the web-root remove probe") + 3]
        self.assertIn("exit 1", block)

    def test_the_failure_names_the_expected_ownership(self) -> None:
        _require(
            'Expected $WEB_ROOT to be $LLDPQ_USER:www-data mode 775',
            INSTALL,
            "install.sh",
        )

    def test_the_probe_follows_the_ownership_it_verifies(self) -> None:
        own = _require(WebRootOwnershipTests.OWN, INSTALL, "install.sh")
        probe = _require(self.PROBE, INSTALL, "install.sh")
        self.assertLess(own, probe)


class LocalPrivilegeDecisionTests(unittest.TestCase):
    """One decision per script, never interactive, never retried per command."""

    # Every converted script and the single form its escalation may take.
    ESCALATIONS = {
        "bin/lldpq": "LLDPQ_PRIV=(sudo -n)",
        "bin/lldpq-trigger": "LLDPQ_PRIV=(sudo -n)",
        "lldpq/check-lldp.sh": "LLDPQ_PRIV=(sudo -n)",
        "lldpq/monitor.sh": "LLDPQ_PRIV=(sudo -n)",
        "lldpq/fabric-scan-cron.sh": "LLDPQ_PRIV=(sudo -n)",
        "lldpq/get-configs.sh": "LLDPQ_PRIV_MODE=sudo",
        "lldpq/lldp-validate.py": 'return ["sudo", "-n"]',
    }

    def test_every_shell_file_touched_stays_valid(self) -> None:
        for relative in SOURCES:
            if not relative.endswith(".py"):
                with self.subTest(relative=relative):
                    subprocess.run(["bash", "-n", str(ROOT / relative)], check=True)

    def test_no_local_publication_site_uses_interactive_sudo(self) -> None:
        for relative, text in LOCAL_TEXT.items():
            with self.subTest(relative=relative):
                offenders = _interactive_sudo_lines(text)
                if offenders:
                    # self.fail, not assertFalse: the latter also prints the
                    # whole offender list as a repr.
                    self.fail(
                        f"{relative} still escalates interactively at "
                        f"{len(offenders)} site(s): {_summarize(offenders)}"
                    )

    def test_the_decision_is_taken_exactly_once_per_script(self) -> None:
        for relative, escalation in self.ESCALATIONS.items():
            with self.subTest(relative=relative):
                self.assertEqual(
                    _count(escalation, SOURCES[relative]),
                    1,
                    f"{relative} must decide once, not per call site",
                )

    def test_every_decision_probes_writability_before_escalating(self) -> None:
        for relative, needle in (
            ("bin/lldpq", 'if [[ ! -w "$WEB_ROOT" ]]; then'),
            ("bin/lldpq-trigger", 'if [[ ! -w "$WEB_ROOT" ]]; then'),
            ("lldpq/monitor.sh", 'if [[ ! -w "$WEB_ROOT" ]]; then'),
            ("lldpq/check-lldp.sh", 'if [[ ! -w "$SCRIPT_DIR/lldp-results" ]]; then'),
            ("lldpq/fabric-scan-cron.sh", 'if [[ ! -w "$CACHE_DIR" ]]; then'),
            ("lldpq/get-configs.sh", '! -w "$WEB_ROOT" ]]; then'),
            ("lldpq/lldp-validate.py", "if os.access(directory, os.W_OK):"),
        ):
            with self.subTest(relative=relative):
                _require(needle, SOURCES[relative], relative)

    def test_the_probe_itself_is_non_interactive(self) -> None:
        for relative in (
            "bin/lldpq",
            "bin/lldpq-trigger",
            "lldpq/check-lldp.sh",
            "lldpq/monitor.sh",
            "lldpq/fabric-scan-cron.sh",
            "lldpq/get-configs.sh",
        ):
            with self.subTest(relative=relative):
                self.assertEqual(
                    _count("sudo -n true 2>/dev/null", SOURCES[relative]),
                    1,
                    f"{relative} must probe with a single non-interactive sudo",
                )
        _require('["sudo", "-n", "true"]', VALIDATE, "lldpq/lldp-validate.py")

    def test_the_failure_names_the_directory_and_the_account(self) -> None:
        for relative, needle in (
            (
                "bin/lldpq",
                '"$WEB_ROOT is not writable by $LLDPQ_USER and passwordless sudo is unavailable"',
            ),
            (
                "bin/lldpq-trigger",
                '"$WEB_ROOT is not writable by $(id -un) and passwordless sudo is unavailable"',
            ),
            (
                "lldpq/monitor.sh",
                '"Error: $WEB_ROOT is not writable by $(id -un) and passwordless sudo is unavailable"',
            ),
            (
                "lldpq/check-lldp.sh",
                '"Error: $WEB_ROOT is not writable by $(id -un) and passwordless sudo is unavailable"',
            ),
            (
                "lldpq/fabric-scan-cron.sh",
                '"fabric-scan-cron: $CACHE_DIR is not writable by $(id -un) and passwordless sudo is unavailable"',
            ),
            (
                "lldpq/get-configs.sh",
                '"$WEB_ROOT is not writable by $(id -un) and passwordless sudo is unavailable"',
            ),
        ):
            with self.subTest(relative=relative):
                _require(needle, SOURCES[relative], relative)
        _require(
            "is not writable by {account} and passwordless sudo ",
            VALIDATE,
            "lldpq/lldp-validate.py",
        )

    def test_no_converted_site_retries_an_unprivileged_attempt_under_sudo(self) -> None:
        """Retrying leaks the temporary a failed mktemp made and can re-apply a move."""
        retry = re.compile(r'\|\|\s*(?:sudo\b|"\$\{LLDPQ_PRIV\[@\]\}")')
        for relative in self.ESCALATIONS:
            with self.subTest(relative=relative):
                offenders = [
                    line.strip()
                    for line in LOCAL_TEXT[relative].split("\n")
                    if retry.search(line)
                ]
                if offenders:
                    self.fail(
                        f"{relative} retries under privilege: {_summarize(offenders)}"
                    )

    def test_check_lldp_decides_before_journal_recovery_runs(self) -> None:
        """The journal only trusts a marker owned by its own euid.

        Recovery and the commit that wrote the marker therefore have to reach the
        same decision, which means deciding before recovery - not after the
        runtime configuration is parsed.
        """
        decision = _require(
            "LLDPQ_PRIV=(sudo -n)", CHECK_LLDP, "lldpq/check-lldp.sh"
        )
        recovery = _require(
            "if ! recover_lldp_outputs; then", CHECK_LLDP, "lldpq/check-lldp.sh"
        )
        self.assertLess(decision, recovery)
        _require(
            '"${LLDPQ_PRIV[@]}" python3 - "$recovery_marker" "$SCRIPT_DIR"',
            CHECK_LLDP,
            "lldpq/check-lldp.sh",
        )

    def test_check_lldp_still_reports_an_unwritable_web_root(self) -> None:
        """$WEB_ROOT is only known after the decision; say so instead of failing
        one write at a time."""
        _require(
            'if [[ ${#LLDPQ_PRIV[@]} -eq 0 && ! -w "$WEB_ROOT" ]]; then',
            CHECK_LLDP,
            "lldpq/check-lldp.sh",
        )


class PublicationTransactionUnchangedTests(unittest.TestCase):
    """Only who runs each command changed; the transaction must not."""

    def test_publish_web_file_keeps_its_exact_command_order(self) -> None:
        start = _require("publish_web_file() {", CHECK_LLDP, "lldpq/check-lldp.sh")
        body = CHECK_LLDP[start : CHECK_LLDP.index("\n}\n", start)]
        order = re.findall(
            r'"\$\{LLDPQ_PRIV\[@\]\}" ([a-z]+)', body
        )
        self.assertEqual(
            order,
            ["mktemp", "cp", "chown", "chmod", "mv", "rm"],
            "staged publication order changed",
        )

    def test_the_monitor_stage_swap_keeps_its_rollback(self) -> None:
        start = _require(
            "activate_monitor_results_stage() {", MONITOR, "lldpq/monitor.sh"
        )
        body = MONITOR[start : MONITOR.index("\n}\n", start)]
        forward = _require(
            '"${LLDPQ_PRIV[@]}" mv -T "$stage_dir" "$destination_dir"',
            body,
            "activate_monitor_results_stage()",
        )
        rollback = _require(
            '"${LLDPQ_PRIV[@]}" mv -T "$backup_dir" "$destination_dir"',
            body,
            "activate_monitor_results_stage()",
        )
        self.assertLess(forward, rollback, "rollback must follow the forward move")
        self.assertIn("CRITICAL: monitor web rollback is retained at", body)

    def test_the_full_publish_still_stages_a_sibling_tree_first(self) -> None:
        start = _require(
            "publish_full_monitor_results() {", MONITOR, "lldpq/monitor.sh"
        )
        body = MONITOR[start : start + 1200]
        stage = _require(
            '"${LLDPQ_PRIV[@]}" mktemp -d "$WEB_ROOT/.monitor-results.new.XXXXXXXXXX"',
            body,
            "publish_full_monitor_results()",
        )
        copy = _require('"${LLDPQ_PRIV[@]}" cp -a', body, "publish_full_monitor_results()")
        self.assertLess(stage, copy)

    def test_the_scoped_publish_still_guards_the_protected_authority(self) -> None:
        _require(
            "Scoped publication changed protected authority", MONITOR, "lldpq/monitor.sh"
        )

    def test_get_configs_call_sites_were_not_rewritten_at_all(self) -> None:
        """root_run already existed, so the decision lands in one function body."""
        for needle in (
            'temp_destination=$(root_run mktemp "$(dirname "$destination_file")/.lldpq-config-publish.XXXXXXXXXX")',
            'root_run mv -fT "$temp_destination" "$destination_file"',
            'root_run mkdir -p "$WEB_CONFIG_DIR"',
        ):
            with self.subTest(needle=needle):
                _require(needle, GET_CONFIGS, "lldpq/get-configs.sh")

    def test_the_validator_keeps_the_legacy_rollback_path(self) -> None:
        _require("CRITICAL: could not restore previous LLDP report", VALIDATE,
                 "lldpq/lldp-validate.py")
        _require(
            "[*local_publication_command(web_topology_directory()),",
            VALIDATE,
            "lldpq/lldp-validate.py",
        )


class PublishEquivalenceTests(unittest.TestCase):
    """Prove the substitution changed only who runs each command.

    Every external tool publish_web_file uses is stubbed to record its argv, so
    the two privilege modes can be compared instruction for instruction without
    depending on GNU-only flags such as `mv -fT`.
    """

    TOOLS = ("cp", "chown", "chmod", "mv", "rm")

    def _record(self, privilege: str) -> list[str]:
        start = _require("publish_web_file() {", CHECK_LLDP, "lldpq/check-lldp.sh")
        body = CHECK_LLDP[start : CHECK_LLDP.index("\n}\n", start) + 3]
        with tempfile.TemporaryDirectory() as tmp:
            stub_dir = Path(tmp) / "bin"
            stub_dir.mkdir()
            log = Path(tmp) / "argv.log"
            for tool in self.TOOLS:
                stub = stub_dir / tool
                stub.write_text(
                    f'#!/bin/sh\nprintf "{tool} %s\\n" "$*" >> "$ARGV_LOG"\nexit 0\n',
                    encoding="utf-8",
                )
                stub.chmod(0o755)
            (stub_dir / "mktemp").write_text(
                '#!/bin/sh\nprintf "mktemp %s\\n" "$*" >> "$ARGV_LOG"\n'
                'printf "%s\\n" "$1"\n',
                encoding="utf-8",
            )
            (stub_dir / "mktemp").chmod(0o755)
            # sudo -n records itself and then runs what it was asked to run, so
            # the escalated mode produces the same tool sequence.
            (stub_dir / "sudo").write_text(
                '#!/bin/sh\nprintf "sudo %s\\n" "$1" >> "$ARGV_LOG"\nshift\nexec "$@"\n',
                encoding="utf-8",
            )
            (stub_dir / "sudo").chmod(0o755)
            script = (
                f"declare -a LLDPQ_PRIV=({privilege})\n"
                'LLDPQ_USER="tester"\n'
                + body
                + f'\npublish_web_file "{tmp}/source" "{tmp}/destination"\n'
                'printf "status=%s\\n" "$?"\n'
            )
            completed = subprocess.run(
                ["bash", "-c", script],
                capture_output=True,
                text=True,
                env=dict(
                    os.environ,
                    PATH=f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                    ARGV_LOG=str(log),
                ),
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("status=0", completed.stdout, completed.stderr)
            # Each run gets its own scratch directory; normalize it away so the
            # two privilege modes are comparable.
            return [
                line.replace(tmp, "<scratch>")
                for line in log.read_text(encoding="utf-8").splitlines()
            ]

    def test_the_unprivileged_mode_runs_the_original_command_sequence(self) -> None:
        recorded = self._record("")
        self.assertEqual(
            [line.split(" ", 1)[0] for line in recorded],
            ["mktemp", "cp", "chown", "chmod", "mv"],
            "the publication sequence changed",
        )
        self.assertNotIn("sudo", " ".join(recorded))

    def test_escalated_and_unprivileged_modes_issue_identical_commands(self) -> None:
        plain = self._record("")
        escalated = [
            line for line in self._record("sudo -n") if not line.startswith("sudo ")
        ]
        if plain != escalated:
            differing = [
                f"{left!r} vs {right!r}"
                for left, right in zip(plain, escalated)
                if left != right
            ]
            self.fail(
                "escalation changed more than who runs each command: "
                f"{_summarize(differing, 2)}"
            )

    def test_the_escalated_mode_only_ever_passes_the_non_interactive_flag(self) -> None:
        escalated = self._record("sudo -n")
        flags = sorted({line for line in escalated if line.startswith("sudo ")})
        self.assertEqual(flags, ["sudo -n"])
        self.assertEqual(
            sum(1 for line in escalated if line == "sudo -n"),
            5,
            "every publication command must be escalated the same way",
        )


class RemoteSudoUntouchedTests(unittest.TestCase):
    """sudo on a switch, over SSH, is the switch's own and must stay bare."""

    REMOTE_CALLS = {
        "lldpq/check-lldp.sh": ("sudo lldpctl 2>/dev/null",),
        "lldpq/monitor.sh": (
            "_lldpq_run_bounded sudo /usr/sbin/bridge vlan",
            "_lldpq_run_bounded sudo /usr/sbin/bridge fdb show",
            '_lldpq_run_bounded sudo vtysh -c "show bgp vrf all sum"',
            '_lldpq_run_bounded sudo vtysh -c "show bgp l2vpn evpn"',
            '_lldpq_run_bounded sudo vtysh -c "show evpn es-evi"',
            "_lldpq_run_bounded sudo l1-show all -p",
            "_lldpq_run_bounded sudo journalctl",
            "_lldpq_run_bounded sudo dmesg",
            'sudo ethtool -m "$interface" 2>/dev/null',
        ),
        "lldpq/collect-transceiver-fw.sh": (
            "timeout 5 sudo mlxlink -d /dev/mst/$MST_DEV -m -p $port_num",
        ),
    }

    def test_the_remote_calls_are_still_present(self) -> None:
        for relative, calls in self.REMOTE_CALLS.items():
            for call in calls:
                with self.subTest(relative=relative, call=call):
                    _require(call, REMOTE_TEXT[relative], f"{relative} remote payload")

    def test_the_remote_calls_are_not_in_the_local_half(self) -> None:
        for relative, calls in self.REMOTE_CALLS.items():
            for call in calls:
                with self.subTest(relative=relative, call=call):
                    self.assertNotIn(
                        call,
                        LOCAL_TEXT[relative],
                        f"{relative}: {call!r} escaped the SSH payload",
                    )

    def test_no_remote_call_was_given_the_local_prefix(self) -> None:
        for relative in self.REMOTE_CALLS:
            with self.subTest(relative=relative):
                self.assertNotIn(
                    "LLDPQ_PRIV",
                    REMOTE_TEXT[relative],
                    f"{relative}: the local decision leaked into the remote payload",
                )

    def test_the_config_collector_still_reads_startup_yaml_over_ssh(self) -> None:
        _require(
            '"sudo cat /etc/nvue.d/startup.yaml"', GET_CONFIGS, "lldpq/get-configs.sh"
        )

    def test_the_already_degrading_local_sites_were_left_alone(self) -> None:
        """assets.sh and the transceiver publisher already fell back gracefully."""
        _require(
            "sudo -n dmidecode -s system-serial-number", ASSETS, "lldpq/assets.sh"
        )
        _require('"$ASSETS_SUDO_BIN" -n install -m 664', ASSETS, "lldpq/assets.sh")
        _require('sudo -n mkdir -p "$WEB_MONITOR_DIR"', TRANSCEIVER,
                 "lldpq/collect-transceiver-fw.sh")


@unittest.skipIf(os.geteuid() == 0, "root can write any directory")
class DecisionBehaviourTests(unittest.TestCase):
    """Run the installed decision block against a real unwritable directory."""

    BLOCKS = {
        "lldpq/monitor.sh": ('if [[ ! -w "$WEB_ROOT" ]]; then', "WEB_ROOT"),
        "bin/lldpq-trigger": ('if [[ ! -w "$WEB_ROOT" ]]; then', "WEB_ROOT"),
        "lldpq/fabric-scan-cron.sh": ('if [[ ! -w "$CACHE_DIR" ]]; then', "CACHE_DIR"),
    }

    def _block(self, relative: str) -> str:
        opener, _variable = self.BLOCKS[relative]
        text = SOURCES[relative]
        start = _require(opener, text, relative)
        end = _require("\nfi\n", text[start:], f"{relative} decision block")
        return text[start : start + end + 4]

    def _run(self, relative: str, target: Path, sudo_status: int):
        opener, variable = self.BLOCKS[relative]
        del opener
        with tempfile.TemporaryDirectory() as tmp:
            stub_dir = Path(tmp)
            calls = stub_dir / "sudo.calls"
            sudo = stub_dir / "sudo"
            sudo.write_text(
                "#!/bin/sh\n"
                'printf "%s\\n" "$*" >> "$LLDPQ_SUDO_CALLS"\n'
                f"exit {sudo_status}\n",
                encoding="utf-8",
            )
            sudo.chmod(0o755)
            script = (
                f'{variable}="{target}"\n'
                "declare -a LLDPQ_PRIV=()\n"
                "trigger_fatal() { echo \"$*\" >&2; exit 1; }\n"
                + self._block(relative)
                + '\nprintf "PRIV=%s\\n" "${LLDPQ_PRIV[*]}"\n'
            )
            environment = dict(
                os.environ,
                PATH=f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                LLDPQ_SUDO_CALLS=str(calls),
                LLDPQ_USER="tester",
            )
            completed = subprocess.run(
                ["bash", "-c", script],
                capture_output=True,
                text=True,
                env=environment,
                timeout=30,
            )
            recorded = (
                calls.read_text(encoding="utf-8").splitlines()
                if calls.exists()
                else []
            )
            return completed, recorded

    def test_a_writable_directory_needs_no_privilege_at_all(self) -> None:
        """The whole point: a correctly installed host never escalates."""
        for relative in self.BLOCKS:
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as writable:
                    completed, recorded = self._run(relative, Path(writable), 0)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("PRIV=\n", completed.stdout)
                self.assertEqual(recorded, [], "sudo was consulted unnecessarily")

    def test_an_unwritable_directory_escalates_non_interactively(self) -> None:
        for relative in self.BLOCKS:
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as tmp:
                    closed = Path(tmp) / "closed"
                    closed.mkdir(mode=0o500)
                    completed, recorded = self._run(relative, closed, 0)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("PRIV=sudo -n\n", completed.stdout)
                self.assertEqual(recorded, ["-n true"])

    def test_without_passwordless_sudo_it_fails_naming_the_directory(self) -> None:
        for relative in self.BLOCKS:
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as tmp:
                    closed = Path(tmp) / "closed"
                    closed.mkdir(mode=0o500)
                    completed, recorded = self._run(relative, closed, 1)
                    self.assertEqual(completed.returncode, 1)
                    self.assertIn(str(closed), completed.stderr)
                self.assertIn("passwordless sudo is unavailable", completed.stderr)
                self.assertEqual(recorded, ["-n true"])

    def test_no_probe_or_escalation_ever_omits_the_non_interactive_flag(self) -> None:
        for relative in self.BLOCKS:
            for status in (0, 1):
                with self.subTest(relative=relative, status=status):
                    with tempfile.TemporaryDirectory() as tmp:
                        closed = Path(tmp) / "closed"
                        closed.mkdir(mode=0o500)
                        _completed, recorded = self._run(relative, closed, status)
                    for call in recorded:
                        self.assertTrue(
                            call.startswith("-n"),
                            f"{relative} invoked sudo interactively: {call!r}",
                        )


class TriggerFailureReasonTests(unittest.TestCase):
    """The trigger must keep the collector's reason, not just its exit status."""

    def test_no_collector_output_is_discarded_any_more(self) -> None:
        offenders = [
            line.strip()
            for line in TRIGGER.split("\n")
            if ">/dev/null 2>&1" in line and "./" in line
        ]
        if offenders:
            self.fail(
                "bin/lldpq-trigger still discards collector output: "
                f"{_summarize(offenders)}"
            )

    def test_every_collector_runs_through_the_logging_wrapper(self) -> None:
        for collector in (
            "./assets.sh",
            "./check-lldp.sh",
            "./monitor.sh",
            "./get-configs.sh",
            "./collect-transceiver-fw.sh",
        ):
            with self.subTest(collector=collector):
                # A line continuation may sit between the two, so this crosses
                # newlines; assertRegex would print the whole daemon on failure.
                pattern = re.compile(
                    r"run_logged_collector[\s\S]{0,120}?" + re.escape(collector)
                )
                self.assertTrue(
                    pattern.search(TRIGGER),
                    f"bin/lldpq-trigger no longer logs the output of {collector}",
                )

    def test_the_log_is_readable_by_the_web_user(self) -> None:
        _require('chmod 664 "$TRIGGER_LOG_FILE"', TRIGGER, "bin/lldpq-trigger")
        _require(
            'TRIGGER_LOG_FILE="${LLDPQ_TRIGGER_LOG_FILE:-$LLDPQ_DIR/trigger-refresh.log}"',
            TRIGGER,
            "bin/lldpq-trigger",
        )

    def test_the_log_is_bounded(self) -> None:
        _require("trim_trigger_log", TRIGGER, "bin/lldpq-trigger")
        _require(
            'TRIGGER_LOG_MAX_LINES="${LLDPQ_TRIGGER_LOG_MAX_LINES:-2000}"',
            TRIGGER,
            "bin/lldpq-trigger",
        )

    def test_the_excerpt_carried_into_the_status_is_bounded(self) -> None:
        _require(
            'TRIGGER_REASON_EXCERPT_CHARS="${LLDPQ_TRIGGER_REASON_EXCERPT_CHARS:-240}"',
            TRIGGER,
            "bin/lldpq-trigger",
        )
        _require(
            'text="${text:0:TRIGGER_REASON_EXCERPT_CHARS}..."',
            TRIGGER,
            "bin/lldpq-trigger",
        )

    def test_both_job_kinds_publish_the_excerpt_with_the_exit_status(self) -> None:
        for needle in (
            'reason="LLDP refresh failed with status $result; automatic retry in ${delay}s"',
            'reason="Assets refresh failed with status $result; automatic retry in ${delay}s"',
            'detail=$(take_collector_excerpt "$LLDP_EXCERPT_FILE")',
            'detail=$(take_collector_excerpt "$ASSETS_EXCERPT_FILE")',
        ):
            with self.subTest(needle=needle):
                _require(needle, TRIGGER, "bin/lldpq-trigger")
        self.assertEqual(
            _count('reason="$reason; $detail"', TRIGGER),
            2,
            "both LLDP and Assets failures must append the captured reason",
        )

    def test_the_handoff_files_stay_out_of_the_published_report_tree(self) -> None:
        """monitor-results is copied wholesale into the web root."""
        for name in ("LLDP_EXCERPT_FILE", "ASSETS_EXCERPT_FILE", "MONITOR_EXCERPT_FILE"):
            with self.subTest(name=name):
                index = _require(f"{name}=", TRIGGER, "bin/lldpq-trigger")
                line = TRIGGER[index : TRIGGER.index("\n", index)]
                self.assertIn('"$LLDPQ_DIR/.trigger-', line)
                self.assertNotIn("monitor-results", line)


class TriggerLoggingBehaviourTests(unittest.TestCase):
    """Source the daemon's library half and exercise the capture for real."""

    EXCERPT_CHARS = 60

    def _drive(self, body: str, collector: str):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            install_dir = root / "lldpq"
            web_root = root / "html"
            install_dir.mkdir()
            web_root.mkdir()
            config = root / "lldpq.conf"
            config.write_text(
                f"LLDPQ_DIR={install_dir}\n"
                "LLDPQ_USER=tester\n"
                f"WEB_ROOT={web_root}\n",
                encoding="utf-8",
            )
            helper = root / "helper"
            helper.write_text(
                "#!/usr/bin/env bash\n"
                f'exec "{CONFIG_HELPER}" "$@" --config "{config}"\n',
                encoding="utf-8",
            )
            helper.chmod(0o755)
            script = (
                f'. "{TRIGGER_PATH}"\n'
                f"{collector}\n"
                f"{body}\n"
            )
            completed = subprocess.run(
                ["bash", "-c", script],
                capture_output=True,
                text=True,
                env=dict(
                    os.environ,
                    LLDPQ_CONFIG_HELPER=str(helper),
                    LLDPQ_TRIGGER_LIB_ONLY="true",
                    LLDPQ_TRIGGER_REASON_EXCERPT_CHARS=str(self.EXCERPT_CHARS),
                ),
                timeout=60,
            )
            # Read everything before the temporary directory disappears.
            log = install_dir / "trigger-refresh.log"
            if log.exists():
                return completed, log.read_text(encoding="utf-8"), log.stat().st_mode
            return completed, "", 0

    def test_a_failing_collector_leaves_its_stderr_in_the_log(self) -> None:
        completed, log, log_mode = self._drive(
            'run_logged_collector check-lldp.sh "$LLDP_EXCERPT_FILE" broken\n'
            'printf "status=%s\\n" "$?"\n'
            'printf "reason=%s\\n" "$(take_collector_excerpt "$LLDP_EXCERPT_FILE")"\n',
            'broken() { echo "collecting"; echo "Error: /x is not writable" >&2; return 1; }',
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("status=1", completed.stdout)
        self.assertIn("reason=Error: /x is not writable", completed.stdout)
        self.assertIn("check-lldp.sh exit=1", log)
        self.assertIn("Error: /x is not writable", log)
        self.assertIn("collecting", log, "the stdout tail is kept too")
        self.assertEqual(log_mode & 0o777, 0o664, "the web user must be able to read it")

    def test_a_successful_collector_publishes_no_reason(self) -> None:
        completed, log, _ = self._drive(
            'run_logged_collector assets.sh "$ASSETS_EXCERPT_FILE" fine\n'
            'printf "status=%s\\n" "$?"\n'
            'printf "reason=[%s]\\n" "$(take_collector_excerpt "$ASSETS_EXCERPT_FILE")"\n',
            'fine() { echo "done"; return 0; }',
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("status=0", completed.stdout)
        self.assertIn("reason=[]", completed.stdout)
        self.assertIn("assets.sh exit=0", log)

    def test_a_runaway_error_cannot_inflate_the_status_file(self) -> None:
        completed, _log, _ = self._drive(
            'run_logged_collector check-lldp.sh "$LLDP_EXCERPT_FILE" noisy\n'
            'reason=$(take_collector_excerpt "$LLDP_EXCERPT_FILE")\n'
            'printf "length=%s\\n" "${#reason}"\n'
            'printf "tail=%s\\n" "${reason: -3}"\n'
            'printf "lines=%s\\n" "$(printf "%s" "$reason" | wc -l | tr -d " ")"\n',
            'noisy() { head -c 20000 /dev/zero | tr "\\0" "y" >&2; echo >&2; return 1; }',
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        length = int(re.search(r"length=(\d+)", completed.stdout).group(1))
        # Both bounds matter: an empty reason passes a ceiling-only check even
        # when nothing was captured at all.
        self.assertGreater(length, 0, "the reason was not captured")
        self.assertLessEqual(length, self.EXCERPT_CHARS + 3)
        self.assertIn("tail=...", completed.stdout, "truncation is not marked")
        self.assertIn("lines=0", completed.stdout, "the reason must stay one line")

    def test_the_exit_status_of_the_collector_is_returned_unchanged(self) -> None:
        completed, _log, _ = self._drive(
            'run_logged_collector assets.sh "$ASSETS_EXCERPT_FILE" lock_held\n'
            'printf "status=%s\\n" "$?"\n',
            'lock_held() { return 75; }',
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(
            "status=75",
            completed.stdout,
            "lock contention must stay distinguishable from a collection failure",
        )


if __name__ == "__main__":
    unittest.main()
