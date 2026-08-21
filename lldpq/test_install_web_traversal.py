#!/usr/bin/env python3
"""Checks the installer guarantees the web user can actually reach the install tree.

The install tree is `$LLDPQ_USER:www-data` mode 750, which grants www-data read
and traverse *inside* the tree. That is worthless if www-data cannot walk the
parents leading to it, and the default install location is `$HOME/lldpq`.

Recent Ubuntu releases create home directories as 0750 owned by the user's own
group, so www-data is neither the owner nor a group member and `other` has no
bits at all. The tree then looks perfectly correct to the install user while
every CGI stat inside it fails. `html/setup-api.sh` reports that as:

    Canonical device parser is missing: /home/<user>/lldpq/parse_devices.py

which points at a file that is present and readable, sending the operator after
the wrong problem entirely.

The installer only ever added www-data to the install user's group inside the
`ANSIBLE_DIR` block, so deployments without Ansible integration had nothing
granting traversal, and deployments with it were fixed by accident.

Reaching the tree is only half of it. Provision and Setup replace devices.yaml
atomically, staging a temporary file next to it and renaming it over the target,
which needs write permission on the *directory*. Mode 750 with group www-data
grants read and traverse only, so the rename failed and `atomic_write_text` fell
through to a branch that blamed a root-owned target - for a file that was never
root-owned. Any chmod of that directory also recalculates the ACL mask and clips
the grant, including the permission hook that runs after every git pull.

These tests pin the surgical grants (ACLs for www-data alone: search on closed
ancestors, write on the install directory), their ordering against every chmod,
the post-install proofs that www-data can both read and stage files, the hook
restoring the mask it would otherwise clip, the honest failure message, and the
web API probe that stops the installer from reporting success over a UI that
cannot authenticate.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
SETUP_API = (ROOT / "html" / "setup-api.sh").read_text(encoding="utf-8")
PROVISION_API = (ROOT / "html" / "provision-api.sh").read_text(encoding="utf-8")


def _extract_function(name: str) -> str:
    """Slice a top-level shell function body out of install.sh."""
    match = re.search(
        r"^%s\(\) \{\n(.*?)^\}\n" % re.escape(name),
        INSTALL,
        re.DOTALL | re.MULTILINE,
    )
    return match.group(0) if match else ""


def _require(needle: str, haystack: str = INSTALL, label: str = "install.sh") -> int:
    """Locate a marker, reporting a one-line message rather than dumping the file.

    A plain assertIn against a 300 KB script buries the real message in the
    whole file, so every lookup here goes through this instead.
    """
    index = haystack.find(needle)
    if index < 0:
        raise AssertionError(f"{label} no longer contains: {needle!r}")
    return index


TRAVERSAL_FN = _extract_function("ensure_web_traversal")

# www-data cannot be impersonated by a test runner, so `sudo` becomes a shell
# function: traversal is answered from a list of paths the test controls, and
# setfacl records what it was asked to open and then opens it.
SUDO_SHIM = """
sudo() {
    if [ "$1" = "-u" ] && [ "$2" = "www-data" ]; then
        shift 2
        if grep -Fxq "$3" "$TRAVERSABLE"; then
            return 0
        fi
        return 1
    fi
    if [ "$1" = "setfacl" ]; then
        printf '%s\\n' "$4" >> "$SETFACL_LOG"
        printf '%s\\n' "$4" >> "$TRAVERSABLE"
        return 0
    fi
    "$@"
}
"""


class TraversalGrantTests(unittest.TestCase):
    """The grant must be surgical and must cover every closed ancestor."""

    def setUp(self) -> None:
        if not TRAVERSAL_FN:
            self.fail("install.sh no longer defines ensure_web_traversal()")

    def _run(self, target: str, traversable: list[str]) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            traversable_file = Path(tmp) / "traversable"
            setfacl_log = Path(tmp) / "setfacl"
            traversable_file.write_text(
                "".join(f"{path}\n" for path in traversable), encoding="utf-8"
            )
            setfacl_log.write_text("", encoding="utf-8")
            script = (
                "set -e\n"
                f'TRAVERSABLE="{traversable_file}"\n'
                f'SETFACL_LOG="{setfacl_log}"\n'
                + SUDO_SHIM
                + TRAVERSAL_FN
                + f'\nensure_web_traversal "{target}"\n'
            )
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, timeout=30
            )
            self.assertEqual(
                result.returncode, 0, f"grant failed: {result.stderr.strip()}"
            )
            return [
                line
                for line in setfacl_log.read_text(encoding="utf-8").splitlines()
                if line
            ]

    def test_a_closed_home_directory_is_opened_for_the_web_user(self) -> None:
        granted = self._run(
            "/home/someone/lldpq",
            traversable=["/home"],
        )
        self.assertIn("/home/someone", granted)
        self.assertIn("/home/someone/lldpq", granted)

    def test_an_already_traversable_parent_is_left_alone(self) -> None:
        granted = self._run(
            "/opt/lldpq",
            traversable=["/opt", "/opt/lldpq"],
        )
        self.assertEqual(
            granted, [], "nothing should be modified when traversal already works"
        )

    def test_only_the_closed_components_are_touched(self) -> None:
        granted = self._run(
            "/srv/data/lldpq",
            traversable=["/srv", "/srv/data/lldpq"],
        )
        self.assertEqual(granted, ["/srv/data"])

    def test_the_root_directory_is_never_modified(self) -> None:
        granted = self._run("/home/someone/lldpq", traversable=[])
        self.assertNotIn("/", granted)

    def test_every_ancestor_is_considered_not_just_the_parent(self) -> None:
        granted = self._run("/a/b/c/lldpq", traversable=[])
        self.assertEqual(granted, ["/a", "/a/b", "/a/b/c", "/a/b/c/lldpq"])


class TraversalWiringTests(unittest.TestCase):
    """Static wiring: the grant has to run, in the right place, for the real path."""

    def test_the_grant_is_invoked_for_the_install_directory(self) -> None:
        _require('ensure_web_traversal "$LLDPQ_INSTALL_DIR"')

    def test_the_grant_is_fatal_when_it_cannot_open_the_path(self) -> None:
        start = _require('if ! ensure_web_traversal "$LLDPQ_INSTALL_DIR"')
        block = INSTALL[start:]
        block = block[: _require("fi\n", block, "the traversal guard") + 3]
        self.assertIn("exit 1", block)

    def test_the_grant_names_only_the_web_user(self) -> None:
        _require("u:www-data:x", TRAVERSAL_FN, "ensure_web_traversal()")
        self.assertNotIn("o+x", TRAVERSAL_FN)
        self.assertNotIn("usermod", TRAVERSAL_FN)

    def test_the_grant_runs_after_ownership_is_applied(self) -> None:
        needle = 'sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR"\n'
        _require(needle)
        chown = INSTALL.rindex(needle)
        grant = _require('ensure_web_traversal "$LLDPQ_INSTALL_DIR"')
        self.assertLess(
            chown, grant, "traversal must be granted after the tree is chowned"
        )


class WebReadProofTests(unittest.TestCase):
    """The installer must prove the web user can read the tree, not assume it."""

    def test_the_parser_readability_is_verified_as_the_web_user(self) -> None:
        _require('sudo -u www-data test -r "$LLDPQ_INSTALL_DIR/parse_devices.py"')

    def test_a_failed_proof_stops_the_installer(self) -> None:
        start = _require(
            'sudo -u www-data test -r "$LLDPQ_INSTALL_DIR/parse_devices.py"'
        )
        tail = INSTALL[start:]
        block = tail[: _require("fi\n", tail, "the readability proof") + 3]
        self.assertIn("exit 1", block)

    def test_the_failure_message_names_the_symptom_operators_will_see(self) -> None:
        _require("Canonical device parser is missing")

    def test_the_verified_file_is_the_one_setup_actually_requires(self) -> None:
        self.assertTrue((ROOT / "lldpq" / "parse_devices.py").is_file())
        _require("'parse_devices.py'", SETUP_API, "html/setup-api.sh")

    def test_the_parser_survives_the_post_copy_cleanup(self) -> None:
        start = _require('sudo cp -r lldpq/* "$LLDPQ_INSTALL_DIR/"')
        block = INSTALL[start : start + 600]
        removed = re.findall(r'"\$LLDPQ_INSTALL_DIR/([A-Za-z0-9_.-]+\.py)"', block)
        self.assertNotIn("parse_devices.py", removed)


class WriteGrantTests(unittest.TestCase):
    """Atomic devices.yaml saves need directory write, not just file write."""

    def test_the_web_user_is_granted_write_on_the_install_directory(self) -> None:
        _require('sudo setfacl -m u:www-data:rwx "$LLDPQ_INSTALL_DIR"')

    def test_the_write_grant_runs_after_the_directory_mode_is_set(self) -> None:
        needle = 'sudo chmod 750 "$LLDPQ_INSTALL_DIR"'
        _require(needle)
        chmod = INSTALL.rindex(needle)
        grant = _require('sudo setfacl -m u:www-data:rwx "$LLDPQ_INSTALL_DIR"')
        self.assertLess(
            chmod, grant, "chmod recalculates the mask and would clip the grant"
        )

    def test_a_failed_write_grant_stops_the_installer(self) -> None:
        start = _require('if ! sudo setfacl -m u:www-data:rwx "$LLDPQ_INSTALL_DIR"')
        tail = INSTALL[start:]
        block = tail[: _require("fi\n", tail, "the write grant") + 3]
        self.assertIn("exit 1", block)

    def test_the_write_is_proven_functionally_as_the_web_user(self) -> None:
        _require('sudo -u www-data touch "$_web_write_probe"')

    def test_a_failed_write_probe_stops_the_installer(self) -> None:
        start = _require('if ! sudo -u www-data touch "$_web_write_probe"')
        tail = INSTALL[start:]
        block = tail[: _require("fi\n", tail, "the write probe") + 3]
        self.assertIn("exit 1", block)

    def test_the_probe_file_is_removed_before_and_after_the_attempt(self) -> None:
        start = _require('_web_write_probe="$LLDPQ_INSTALL_DIR/')
        block = INSTALL[start : start + 800]
        self.assertGreaterEqual(block.count('sudo rm -f "$_web_write_probe"'), 2)


class GitHookMaskTests(unittest.TestCase):
    """The permission hook must not clip the grant on every pull."""

    RESTORE = 'setfacl -m u:www-data:rwx "$(git rev-parse --show-toplevel)"'

    def test_both_hook_copies_restore_the_grant(self) -> None:
        self.assertEqual(
            INSTALL.count(self.RESTORE),
            2,
            "the update-mode and fresh-install hook copies both need the restore",
        )

    def test_the_restore_follows_the_chmod_in_every_hook(self) -> None:
        chmods = [
            match.start()
            for match in re.finditer(
                r'chmod 750 "\$\(git rev-parse --show-toplevel\)"', INSTALL
            )
        ]
        self.assertTrue(chmods, "the hook no longer chmods the toplevel")
        for index in chmods:
            self.assertIn(self.RESTORE, INSTALL[index : index + 500])

    def test_the_restore_tolerates_a_host_without_setfacl(self) -> None:
        start = _require(self.RESTORE)
        self.assertIn("command -v setfacl", INSTALL[max(0, start - 250) : start])


class AtomicWriteErrorTests(unittest.TestCase):
    """The failure has to name the real cause, not a presumed one."""

    def test_the_misleading_root_owned_message_is_gone(self) -> None:
        stale = "Atomic replacement is not permitted for root-owned"
        self.assertEqual(
            PROVISION_API.count(stale),
            0,
            f"html/provision-api.sh still blames a root-owned target: {stale!r}",
        )

    def test_the_real_error_is_reported(self) -> None:
        _require(
            "Could not atomically replace {path}: {primary_error}",
            PROVISION_API,
            "html/provision-api.sh",
        )

    def test_the_first_failure_is_captured_rather_than_discarded(self) -> None:
        _require(
            "except (OSError, subprocess.SubprocessError) as exc:",
            PROVISION_API,
            "html/provision-api.sh",
        )
        _require("primary_error = exc", PROVISION_API, "html/provision-api.sh")

    def test_the_message_names_the_directory_that_needs_write(self) -> None:
        _require(
            "must be writable by this user", PROVISION_API, "html/provision-api.sh"
        )


class WebApiProbeTests(unittest.TestCase):
    """A finished copy is not a working UI; the installer must probe the API."""

    def test_the_auth_endpoint_is_probed_before_reporting_success(self) -> None:
        probe = _require("/auth-api?action=check")
        banner = _require("LLDPq Installation Complete!")
        self.assertLess(probe, banner)

    def test_the_probe_does_not_depend_on_jq(self) -> None:
        start = _require("_api_status=$(curl")
        block = INSTALL[start : start + 300]
        self.assertNotIn("jq", block)

    def test_a_failed_probe_is_surfaced_after_the_banner(self) -> None:
        banner = _require("LLDPq Installation Complete!")
        _require('if [[ -n "$_api_warning" ]]', INSTALL[banner:], "the banner block")

    def test_the_probe_failure_explains_what_the_browser_will_show(self) -> None:
        _require("Auth check unreachable")

    def test_the_probe_tolerates_a_missing_listen_directive(self) -> None:
        start = _require("_api_port=$(grep")
        block = INSTALL[start : start + 300]
        self.assertIn("|| true", block)
        self.assertIn("_api_port=${_api_port:-80}", block)


if __name__ == "__main__":
    unittest.main()
