#!/usr/bin/env python3
"""Checks the installer leaves the runtime data trees writable by both sides.

`monitor-results/` is written from two directions: cron and the CLI run as
$LLDPQ_USER, while the web UI's CGI writes analysis output as www-data. That
only works when the tree is $LLDPQ_USER:www-data with group write.

The installer used to create it *after* its recursive chown of the install
directory, and never chowned it again:

    sudo chown -R "$LLDPQ_USER:www-data" "$LLDPQ_INSTALL_DIR"
    ...
    sudo mkdir -p "$LLDPQ_INSTALL_DIR/monitor-results/fabric-tables"
    sudo chmod 750 "$LLDPQ_INSTALL_DIR/monitor-results"

On a fresh install the directory does not exist in the copied source, so
`sudo mkdir` created it root:root, and 750 then denied the install user
everything — collection and the web UI both broke until an operator ran
`chown -R` by hand. The only corrective chown lived in the update-only restore
block, which is why in-place updates looked healthy and every genuinely fresh
install did not.

The mode was inconsistent too: the fresh path set 750 while the update path set
775 on directories and 664 on files. 750 with group www-data grants traverse
and read but not write, so it can never satisfy the web UI.

These tests pin the ordering (create before claiming ownership), the resulting
modes, and the sibling runtime trees the update path already guaranteed.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text(encoding="utf-8")
ENTRYPOINT = (ROOT / "docker" / "docker-entrypoint.sh").read_text(encoding="utf-8")

RUNTIME_TREES = ("monitor-results", "lldp-results", "alert-states")

# Anchors chosen to exist both before and after the fix, so a regression fails
# on an assertion rather than on a missing slice.
_BLOCK_START = INSTALL.index('sudo mkdir -p "$LLDPQ_INSTALL_DIR/monitor-results')
_BLOCK_END = INSTALL.index("# Set default ACL", _BLOCK_START)
PERMISSION_BLOCK = INSTALL[_BLOCK_START:_BLOCK_END]

# `sudo` is replaced by a shell function so the block can run unprivileged:
# mkdir/chmod/find act for real, chown is only recorded because no test runner
# may hand out www-data.
SUDO_SHIM = """
sudo() {
    if [ "$1" = "chown" ]; then
        shift
        printf '%s\\n' "$*" >> "$CHOWN_LOG"
        return 0
    fi
    "$@"
}
"""

TEST_USER = "lldpq-test-user"


def _find_exec_plus_available() -> bool:
    """`find -exec ... {} +` needs sysconf(_SC_ARG_MAX), which some sandboxes deny.

    The installer relies on that form, so a runner that cannot use it can only
    report a false failure for the functional probe below.
    """
    with tempfile.TemporaryDirectory(dir=ROOT) as probe:
        completed = subprocess.run(
            ["find", probe, "-type", "d", "-exec", "chmod", "775", "{}", "+"],
            capture_output=True,
        )
    return completed.returncode == 0


class InstallerRuntimeOwnershipTests(unittest.TestCase):
    def test_install_sh_stays_valid_shell(self):
        subprocess.run(["bash", "-n", str(ROOT / "install.sh")], check=True)

    def test_the_block_is_located_unambiguously(self):
        occurrences = INSTALL.count(
            'sudo mkdir -p "$LLDPQ_INSTALL_DIR/monitor-results'
        )
        self.assertEqual(occurrences, 1, "runtime mkdir is no longer unique")

    # ---------- ordering: the defect itself ----------
    def test_every_runtime_tree_is_created_before_ownership_is_claimed(self):
        """The bug was pure ordering: mkdir ran after the last recursive chown."""
        for tree in RUNTIME_TREES:
            with self.subTest(tree=tree):
                created = re.search(
                    r'mkdir -p(?:[^\n]|\\\n)*?'
                    rf'"\$LLDPQ_INSTALL_DIR/{re.escape(tree)}',
                    PERMISSION_BLOCK,
                )
                self.assertIsNotNone(
                    created, f"{tree} is never created by the installer"
                )
                claimed = re.search(
                    r'chown -R "\$LLDPQ_USER:www-data"(?:[^\n]|\\\n)*?'
                    rf'"\$LLDPQ_INSTALL_DIR/(?:\$_runtime_item|{re.escape(tree)})',
                    PERMISSION_BLOCK,
                )
                self.assertIsNotNone(
                    claimed, f"{tree} ownership is never set after creation"
                )
                self.assertLess(
                    created.start(),
                    claimed.start(),
                    f"{tree} is chowned before it is created",
                )

    def test_the_fresh_path_no_longer_sets_750_on_a_runtime_tree(self):
        offenders = [
            line.strip()
            for line in PERMISSION_BLOCK.splitlines()
            if "750" in line and not line.strip().startswith("#")
        ]
        self.assertEqual(offenders, [], f"750 still applied: {offenders}")

    def test_the_shared_modes_are_the_documented_775_and_664(self):
        self.assertIn("-type d -exec chmod 775", PERMISSION_BLOCK)
        self.assertIn("-type f -exec chmod 664", PERMISSION_BLOCK)

    def test_the_install_directory_itself_keeps_its_intentional_750(self):
        """Only monitor-results was wrong; the install root stays 750."""
        # Counted rather than matched: a failed assertIn would print all of
        # install.sh, burying the result it was meant to report.
        self.assertEqual(
            INSTALL.count('sudo chmod 750 "$LLDPQ_INSTALL_DIR"\n'),
            1,
            "the install root no longer gets its intentional 750",
        )

    # ---------- functional: run the installer's own block ----------
    @unittest.skipUnless(
        _find_exec_plus_available(),
        "runner cannot execute `find -exec ... {} +`",
    )
    def test_running_the_block_yields_a_shared_writable_tree(self):
        # Keep the probe inside the repository so sandboxed runners that
        # restrict writes outside the workspace can still chmod it.
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            install_dir = Path(temporary) / "lldpq"
            install_dir.mkdir()
            chown_log = Path(temporary) / "chown.log"
            chown_log.touch()

            # A file left behind by an earlier release, deliberately too tight:
            # a re-install has to widen it to the shared mode.
            stale_tree = install_dir / "monitor-results"
            stale_tree.mkdir()
            stale = stale_tree / "summary.json"
            stale.write_text("{}", encoding="utf-8")
            stale.chmod(0o600)

            subprocess.run(
                ["bash", "-c", SUDO_SHIM + PERMISSION_BLOCK],
                env=dict(
                    os.environ,
                    LLDPQ_INSTALL_DIR=str(install_dir),
                    LLDPQ_USER=TEST_USER,
                    CHOWN_LOG=str(chown_log),
                ),
                check=True,
            )

            for tree in RUNTIME_TREES:
                with self.subTest(tree=tree):
                    created = install_dir / tree
                    self.assertTrue(created.is_dir(), f"{tree} was not created")
                    self.assertEqual(
                        stat.S_IMODE(created.stat().st_mode),
                        0o775,
                        f"{tree} is not group-writable",
                    )

            fabric_tables = install_dir / "monitor-results" / "fabric-tables"
            self.assertTrue(fabric_tables.is_dir())
            self.assertEqual(stat.S_IMODE(fabric_tables.stat().st_mode), 0o775)
            self.assertEqual(stat.S_IMODE(stale.stat().st_mode), 0o664)

            recorded = chown_log.read_text(encoding="utf-8").split("\n")
            for tree in RUNTIME_TREES:
                with self.subTest(tree=tree):
                    self.assertIn(
                        f"-R {TEST_USER}:www-data {install_dir}/{tree}",
                        recorded,
                        f"{tree} was never chowned recursively",
                    )

    # ---------- the git hooks must not undo it ----------
    def test_the_git_hooks_stop_resetting_the_tree_to_750(self):
        """post-merge/post-checkout run in the install dir, not the source."""
        self.assertEqual(
            INSTALL.count(
                'chmod -R 750 "$(git rev-parse --show-toplevel)/monitor-results"'
            ),
            0,
            "a git hook still strips group write from monitor-results",
        )
        hook_fix = (
            'find "$(git rev-parse --show-toplevel)/monitor-results" -type d \\\n'
            "        -exec chmod 775 {} + 2>/dev/null || true\n"
            '    find "$(git rev-parse --show-toplevel)/monitor-results" -type f \\\n'
            "        -exec chmod 664 {} + 2>/dev/null || true"
        )
        # One copy is written on update (restored .git), one on fresh install.
        self.assertEqual(
            INSTALL.count(hook_fix), 2, "both hook copies must apply 775/664"
        )

    def test_the_hooks_still_pin_the_install_root_at_750(self):
        self.assertEqual(
            INSTALL.count('chmod 750 "$(git rev-parse --show-toplevel)"'),
            2,
            "the hooks no longer pin the install root at 750",
        )

    # ---------- the guarantee must not depend on the install mode ----------
    def test_the_update_path_still_enforces_the_same_contract(self):
        for tree in RUNTIME_TREES:
            with self.subTest(tree=tree):
                self.assertGreaterEqual(
                    INSTALL.count(
                        f'sudo chown -R "$LLDPQ_USER:www-data" '
                        f'"$LLDPQ_INSTALL_DIR/{tree}"'
                    ),
                    1,
                    f"the update restore no longer chowns {tree}",
                )

    def test_the_container_and_the_native_install_agree(self):
        """Docker already pre-created these; native had to catch up."""
        for tree in RUNTIME_TREES:
            with self.subTest(tree=tree):
                self.assertIsNotNone(
                    re.search(rf"/lldpq/{re.escape(tree)}\b", ENTRYPOINT),
                    f"the container no longer prepares {tree}",
                )
        self.assertGreaterEqual(
            ENTRYPOINT.count("chown -R lldpq:www-data"),
            1,
            "the container no longer applies the shared owner",
        )
        self.assertGreaterEqual(
            ENTRYPOINT.count("chmod 775"),
            1,
            "the container no longer applies the shared mode",
        )


if __name__ == "__main__":
    unittest.main()
