#!/usr/bin/env python3
"""Regression tests for the Setup offline-update runner generation.

The update-offline handler in html/setup-api.sh builds its runner as a
non-raw triple-quoted SCRIPT literal that embeds a second Python program
(the safe tar extractor) behind a <<'PYSAFE' bash heredoc.  Every escape
in that literal is processed once by the OUTER Python, so the source must
double them (\\\\ / \\x00 / \\n); a single-escaped variant ships a NUL
byte plus a broken string literal in update-run.sh and the extractor dies
with SyntaxError before touching the archive.
"""

from __future__ import annotations

import ast
import io
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SETUP_API = ROOT / "html" / "setup-api.sh"


def embedded_python_source():
    lines = SETUP_API.read_text().splitlines()
    start = lines.index("python3 << 'PYTHON'") + 1
    end = lines.index("PYTHON", start)
    return "\n".join(lines[start:end])


def offline_script_literal():
    """Return the evaluated offline-update SCRIPT string (the generated
    update-run.sh text, marker-substitution aside)."""
    candidates = []
    for node in ast.walk(ast.parse(embedded_python_source())):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "SCRIPT" for t in node.targets):
            continue
        value = ast.literal_eval(node.value)
        if isinstance(value, str) and "PYSAFE" in value:
            candidates.append(value)
    if len(candidates) != 1:
        raise AssertionError(
            "expected exactly one offline SCRIPT literal, found %d" % len(candidates)
        )
    return candidates[0]


def git_update_script_literal():
    """Return the evaluated git-update SCRIPT string (the generated
    update-run.sh text for action=update, marker-substitution aside)."""
    candidates = []
    for node in ast.walk(ast.parse(embedded_python_source())):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "SCRIPT" for t in node.targets):
            continue
        value = ast.literal_eval(node.value)
        if isinstance(value, str) and "git pull" in value:
            candidates.append(value)
    if len(candidates) != 1:
        raise AssertionError(
            "expected exactly one git-update SCRIPT literal, found %d" % len(candidates)
        )
    return candidates[0]


def pysafe_body(script):
    lines = script.splitlines()
    start = next(
        i for i, line in enumerate(lines) if line.endswith("<<'PYSAFE'")
    ) + 1
    end = lines.index("PYSAFE", start)
    return "\n".join(lines[start:end]) + "\n"


class OfflineUpdateScriptGenerationTests(unittest.TestCase):
    def setUp(self):
        self.script = offline_script_literal()

    def test_generated_runner_contains_no_nul_byte(self):
        self.assertNotIn("\x00", self.script)

    def test_pysafe_extractor_compiles(self):
        compile(pysafe_body(self.script), "update-run-pysafe", "exec")

    def test_unsafe_name_checks_survive_escape_processing(self):
        # The generated extractor must keep both checks as source text.
        self.assertIn(r'"\\" in name or "\x00" in name', self.script)

    def test_printf_newlines_stay_escape_sequences(self):
        # A real newline inside the printf format is benign for output but
        # means the source forgot the extra escaping layer.
        self.assertIn(r"printf '%s %s %s\n'", self.script)
        self.assertIn(r"printf '%s %s\n'", self.script)
        self.assertIn(r"printf '__LLDPQ_DONE__:%s\n'", self.script)


class GitUpdateScriptGenerationTests(unittest.TestCase):
    """The action=update (git pull) SCRIPT is a non-raw literal like the
    offline one, so its printf escapes must be doubled the same way."""

    def setUp(self):
        self.script = git_update_script_literal()

    def test_printf_newlines_stay_escape_sequences(self):
        # A real newline inside the printf format is benign for output but
        # means the source forgot the extra escaping layer.
        self.assertIn(r"printf '%s %s %s\n'", self.script)
        self.assertIn(r"printf '%s %s\n'", self.script)
        self.assertIn(r"printf '__LLDPQ_DONE__:%s\n'", self.script)


class OfflineUpdateExtractorEndToEndTests(unittest.TestCase):
    """Runs the exact generated `if ! python3 - ... <<'PYSAFE'` block under
    bash against real tarballs."""

    def setUp(self):
        if shutil.which("bash") is None or shutil.which("python3") is None:
            self.skipTest("bash and python3 are required")
        lines = offline_script_literal().splitlines()
        start = next(
            i for i, line in enumerate(lines)
            if line.lstrip().startswith("if ! python3 - ")
        )
        end = next(i for i in range(start, len(lines)) if lines[i].strip() == "fi")
        self.block = "\n".join(lines[start:end + 1])
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def _make_tarball(self, member_name="lldpq-src/install.sh"):
        payload = b"#!/bin/sh\n"
        tarball = self.root / "src.tar.gz"
        with tarfile.open(tarball, "w:gz") as archive:
            info = tarfile.TarInfo(member_name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        return tarball, payload

    def _run_block(self, tarball):
        destination = self.root / "extract"
        destination.mkdir()
        runner = "\n".join([
            "TARBALL=" + shlex.quote(str(tarball)),
            "TMP=" + shlex.quote(str(destination)),
            self.block,
            "exit 0",
        ])
        result = subprocess.run(["bash", "-c", runner],
                                capture_output=True, text=True)
        return result, destination

    def test_valid_tarball_extracts_and_exits_zero(self):
        tarball, payload = self._make_tarball()
        result, destination = self._run_block(tarball)
        self.assertNotIn("SyntaxError", result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        extracted = destination / "lldpq-src" / "install.sh"
        self.assertEqual(extracted.read_bytes(), payload)

    def test_backslash_member_name_is_rejected_not_a_syntax_error(self):
        tarball, _payload = self._make_tarball(member_name="lldpq-src/bad\\name.sh")
        result, destination = self._run_block(tarball)
        self.assertNotIn("SyntaxError", result.stderr)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("unsafe member name", result.stdout + result.stderr)
        self.assertEqual(list(destination.iterdir()), [])


class BackupImportLockingTests(unittest.TestCase):
    """Source pins: backup-import must serialize against SSH key transactions.

    restore_bundle replaces/retires ~lldpq/.ssh key material (and its
    lock-first recovery can replay a retained key transaction before the new
    bundle is parsed), while the Setup key fan-outs hold ONLY
    /var/lib/lldpq/ssh-key.lock during their multi-minute SSH phase — so the
    import path must extend the shared order to config -> inventory ->
    ssh-key instead of stopping at the config+inventory pair.
    """

    def setUp(self):
        self.tree = ast.parse(embedded_python_source())

    def test_restore_bundle_uses_key_aware_lock_callback(self):
        callbacks = [
            keyword.value.id
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "restore_bundle"
            for keyword in node.keywords
            if keyword.arg == "acquire_lock" and isinstance(keyword.value, ast.Name)
        ]
        self.assertEqual(callbacks, ["ensure_restore_locks"])

    def test_restore_lock_callback_takes_ssh_key_lock(self):
        functions = [
            node for node in ast.walk(self.tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "ensure_restore_locks"
        ]
        self.assertEqual(len(functions), 1)
        called = {
            call.func.id
            for call in ast.walk(functions[0])
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        }
        self.assertIn("ensure_backup_locks", called)
        self.assertIn("ensure_ssh_key_lock", called)


if __name__ == "__main__":
    unittest.main()
