#!/usr/bin/env python3
"""The served ZTP script must carry a password hash, not the password.

`/cumulus-ztp.sh` is fetched by switches before they have any credential, so
nginx serves it without login.  Quick Settings used to write the cumulus
account's password into it as `echo 'cumulus:<password>' | chpasswd`, which
handed the sudo-capable account of every provisioned switch to anyone who
could reach TCP/80.  Saving now stores `echo 'cumulus:<hash>' | chpasswd -e`
with a SHA-512 crypt hash produced by `openssl passwd -6 -stdin`.

Three things make this more than a string swap, and each is pinned here:

* The hash is only useful if the switch's libc verifies it against the
  password the administrator typed.  A stand-in `openssl` proves how the tool
  is called (stdin only, never argv); the real one, where it supports `-6`, is
  checked against an independent implementation of the published algorithm and
  against Python's `crypt` module where that still exists.
* Scripts saved by an earlier version stay on disk in the clear-text form and
  must keep working untouched: the device-upgrade hook is rendered from the
  saved script, so every reader has to understand both forms, and the
  version 1 hook an older job pinned must stay byte-for-byte valid.
* The update scripts can roll back to the previous image on the same volume.
  That image's parsers are quoted here verbatim: they must not match the new
  line, because matching it would mean treating a hash as a password.

The functions are executed straight out of the CGI's embedded Python; the
generated shell is run under bash with stand-in `passwd`/`chpasswd` on PATH.
Whether a real Cumulus `chpasswd -e` accepts the line stays a lab step.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lldpq"))
SOURCE = (ROOT / "html" / "provision-api.sh").read_text(encoding="utf-8").split(
    "python3 << 'PYTHON_SCRIPT'\n", 1)[1].split(
        "# ======================== ROUTER ========================", 1)[0]
ZTP_TEMPLATE = (ROOT / "html" / "cumulus-ztp.sh").read_text(encoding="utf-8")

NAMES = (
    "validate_ztp_script_content", "ztp_script_public_key",
    "ztp_script_static_setting", "hash_ztp_password",
    "hash_ztp_password_lines", "action_save_ztp_script",
    "upgrade_literal_shell_word", "upgrade_literal_assignment",
    "render_upgrade_preserve_hook", "validate_upgrade_preserve_hook_content",
    "prepare_upgrade_post_install_script",
)

# Compiled once: the CGI is large and every test builds a fresh namespace.
_COMPILED = [
    compile(ast.Module(body=[node], type_ignores=[]), "provision-api.sh", "exec")
    for node in ast.parse(SOURCE).body
    if isinstance(node, ast.FunctionDef) and node.name in NAMES
]
assert len(_COMPILED) == len(NAMES), "a function under test is missing"

KEY = "ssh-ed25519 AAAA collector"
HASH_LINE = re.compile(
    r"^(\s*)echo 'cumulus:(\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86})'"
    r" \| chpasswd -e$", re.MULTILINE)
# What the previous release (4.2.x, 5b7d4d8d) used to find the password line.
# Quoted verbatim: these are the parsers a rolled-back image runs.
PREVIOUS_API_PASSWORD_LINE = r'^\s*echo\s+(.+?)\s*\|\s*chpasswd\s*$'
PREVIOUS_UI_PASSWORD_LINE = r"^(\s*)echo\s+'cumulus:.*'\s*\|\s*chpasswd\s*$"
PREVIOUS_HOOK_MARKER = "\n# LLDPQ_UPGRADE_HOOK_VERSION=1\n"

_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_ORDER = ((0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4),
          (47, 5, 26), (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51),
          (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13),
          (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38),
          (18, 39, 60), (40, 61, 19), (62, 20, 41))


def sha512_crypt_reference(key: bytes, salt: bytes, rounds: int = 5000) -> str:
    """SHA-512 crypt as published (Drepper, "Unix crypt using SHA-256/512").

    Independent of openssl and of libc, so the test can tell whether a hash
    really verifies against a password on hosts whose Python has no `crypt`.
    """
    sha = hashlib.sha512
    b = sha(key + salt + key).digest()
    ctx = sha(key + salt)
    ctx.update(b * (len(key) // 64) + b[:len(key) % 64])
    bits = len(key)
    while bits:
        ctx.update(b if bits & 1 else key)
        bits >>= 1
    a = ctx.digest()
    dp = sha(key * len(key)).digest()
    p = dp * (len(key) // 64) + dp[:len(key) % 64]
    s = sha(salt * (16 + a[0])).digest()[:len(salt)]
    c = a
    for index in range(rounds):
        ctx = sha(p if index & 1 else c)
        if index % 3:
            ctx.update(s)
        if index % 7:
            ctx.update(p)
        ctx.update(c if index & 1 else p)
        c = ctx.digest()
    out = []
    for i, j, k in _ORDER:
        value = (c[i] << 16) | (c[j] << 8) | c[k]
        for _ in range(4):
            out.append(_B64[value & 0x3f])
            value >>= 6
    value = c[63]
    for _ in range(2):
        out.append(_B64[value & 0x3f])
        value >>= 6
    return "".join(out)


def verifies(password: str, hashed: str) -> bool:
    """True when `hashed` is the SHA-512 crypt of `password` (default rounds)."""
    _, scheme, salt, digest = hashed.split("$")
    return scheme == "6" and sha512_crypt_reference(
        password.encode("utf-8"), salt.encode("ascii")) == digest


def real_openssl_hashes_sha512() -> bool:
    try:
        result = subprocess.run(
            ["openssl", "passwd", "-6", "-stdin"], input=b"probe\n",
            capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.startswith(b"$6$")


REAL_OPENSSL = real_openssl_hashes_sha512()


class Emitted(BaseException):
    """A CGI response.  Not an Exception, so no `except Exception` swallows it."""

    def __init__(self, payload):
        super().__init__(payload)
        self.payload = payload


def load_api(**extra):
    def result_json(data):
        raise Emitted(data)

    api = {
        "re": re, "shlex": shlex, "subprocess": subprocess, "json": json,
        "os": os, "result_json": result_json,
        "error_json": lambda message: result_json(
            {"success": False, "error": message}),
    }
    api.update(extra)
    for code in _COMPILED:
        exec(code, api)
    return api


def canned_hash(seed: str = "A") -> str:
    return "$6$" + "saltSALT./012345" + "$" + (seed * 86)[:86]


def saved_script(password_line: str, *, version: int = 3) -> str:
    """The shipped template the way Quick Settings fills it in."""
    content = ZTP_TEMPLATE.replace("__TARGET_OS_VERSION__", "5.16.0").replace(
        "__IMAGE_SERVER_IP__", "192.0.2.250").replace(
            'KEY=""', "KEY=" + shlex.quote(KEY)).replace(
                "LLDPQ_ZTP_TEMPLATE_VERSION=3",
                f"LLDPQ_ZTP_TEMPLATE_VERSION={version}")
    replaced, count = re.subn(
        r"^(\s*)echo '[^'\n]*' \| chpasswd(?: -e)?$",
        lambda match: match.group(1) + password_line,
        content, flags=re.MULTILINE)
    assert count == 1, "the shipped template has no single set-password line"
    return replaced


def legacy_line(password: str) -> str:
    """The clear-text form every earlier release wrote."""
    return "echo '%s' | chpasswd" % ("cumulus:" + password).replace("'", "'\\''")


def hashed_line(hashed: str) -> str:
    return f"echo 'cumulus:{hashed}' | chpasswd -e"


class StandInTools(unittest.TestCase):
    """A temporary bin directory placed first on PATH."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.api = load_api()

    def write_tool(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/bash\n" + body + "\n", encoding="utf-8")
        path.chmod(0o755)

    def path_first(self):
        return mock.patch.dict(os.environ, {
            "PATH": f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"})

    def install_fake_openssl(self, reply=None, status=0):
        """Records how it was called; the password must only arrive on stdin."""
        self.reply = canned_hash() if reply is None else reply
        self.write_tool("openssl", "\n".join((
            f'printf "%s\\n" "$#" "$@" > {shlex.quote(str(self.root / "argv"))}',
            f'env > {shlex.quote(str(self.root / "environment"))}',
            f'cat > {shlex.quote(str(self.root / "stdin"))}',
            f'printf "x" >> {shlex.quote(str(self.root / "calls"))}',
            f"printf '%s\\n' {shlex.quote(self.reply)}",
            f"exit {status}",
        )))

    def openssl_calls(self):
        calls = self.root / "calls"
        return len(calls.read_text()) if calls.exists() else 0


class PasswordHashingToolTests(StandInTools):
    PASSWORD = "S3cret $(id) `x` it's"

    def test_the_password_reaches_openssl_on_stdin_only(self):
        self.install_fake_openssl()
        # The CGI exports the request body, which carries the password.
        request = json.dumps({"content": legacy_line(self.PASSWORD)})
        with self.path_first(), mock.patch.dict(os.environ,
                                                {"POST_DATA": request}):
            hashed = self.api["hash_ztp_password"](self.PASSWORD)
        self.assertEqual(hashed, self.reply)
        self.assertEqual((self.root / "argv").read_text().splitlines(),
                         ["3", "passwd", "-6", "-stdin"])
        self.assertEqual((self.root / "stdin").read_bytes(),
                         self.PASSWORD.encode("utf-8") + b"\n")
        environment = (self.root / "environment").read_text()
        self.assertNotIn(self.PASSWORD, environment)
        self.assertNotIn("POST_DATA", environment)
        self.assertIn("PATH=", environment)

    def test_a_non_ascii_password_is_hashed_as_utf8(self):
        self.install_fake_openssl()
        with self.path_first():
            self.api["hash_ztp_password"]("pässwörd ✓")
        self.assertEqual((self.root / "stdin").read_bytes(),
                         "pässwörd ✓".encode("utf-8") + b"\n")

    def test_unusable_passwords_never_reach_the_tool(self):
        self.install_fake_openssl()
        # openssl would silently hash a 256-byte prefix of the last one.
        for password in ("", "two\nlines", "carriage\rreturn", "nul\x00byte",
                         "a" * 129, "✓" * 100, None):
            with self.subTest(password=password), self.path_first():
                with self.assertRaises(ValueError):
                    self.api["hash_ztp_password"](password)
        self.assertEqual(self.openssl_calls(), 0)

    def test_a_tool_failure_is_reported_without_the_password(self):
        for reply, status in ((canned_hash(), 1), ("not a hash", 0),
                              ("$1$salt$md5md5md5md5md5md5md5m", 0), ("", 0)):
            self.install_fake_openssl(reply=reply, status=status)
            with self.subTest(reply=reply, status=status), self.path_first():
                with self.assertRaises(ValueError) as failure:
                    self.api["hash_ztp_password"](self.PASSWORD)
                self.assertNotIn(self.PASSWORD, str(failure.exception))
                self.assertIn("openssl", str(failure.exception))

    def test_a_missing_tool_is_reported_not_raised_as_oserror(self):
        with mock.patch.dict(os.environ, {"PATH": str(self.bin)}):
            with self.assertRaisesRegex(ValueError, "openssl did not run"):
                self.api["hash_ztp_password"](self.PASSWORD)


class ReferenceImplementationTests(unittest.TestCase):
    def test_the_reference_matches_the_published_vectors(self):
        # The guide's on-switch one-liner compares libc's crypt() to the
        # first of these, so it has to stay the published value.
        self.assertEqual(
            sha512_crypt_reference(b"Hello world!", b"saltstring"),
            "svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68"
            "u4OTLiBFdcbYEdFCoEOfaS35inz1")
        self.assertEqual(
            sha512_crypt_reference(b"Hello world!", b"saltstringsaltst", 10000),
            "OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOu"
            "ZeHBy/YTBmSK6H9qs/y3RnOaw5v.")

    def test_verification_rejects_a_wrong_password(self):
        published = ("$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFN"
                     "jnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1")
        self.assertTrue(verifies("Hello world!", published))
        self.assertFalse(verifies("Hello world", published))


@unittest.skipUnless(REAL_OPENSSL, "this openssl has no 'passwd -6'")
class RealHashVerifiesTests(unittest.TestCase):
    PASSWORDS = ("Simple1", "it's $HOME `id` \\ \"quoted\"", "pässwörd ✓",
                 "x" * 128, "é" * 128)

    def setUp(self):
        self.api = load_api()

    def test_the_generated_hash_verifies_against_the_password(self):
        for password in self.PASSWORDS:
            with self.subTest(password=password):
                hashed = self.api["hash_ztp_password"](password)
                self.assertRegex(
                    hashed, r"\A\$6\$[A-Za-z0-9./]{16}\$[A-Za-z0-9./]{86}\Z")
                self.assertTrue(verifies(password, hashed))
                self.assertFalse(verifies(password + "x", hashed))

    def test_two_saves_of_one_password_use_different_salts(self):
        first = self.api["hash_ztp_password"]("Simple1")
        second = self.api["hash_ztp_password"]("Simple1")
        self.assertNotEqual(first, second)

    def test_the_hash_verifies_with_the_crypt_module_where_available(self):
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                import crypt
        except ImportError:
            self.skipTest("this Python has no crypt module (removed in 3.13)")
        known = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFN" \
                "jnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
        if crypt.crypt("Hello world!", known) != known:
            self.skipTest("this libc's crypt() has no SHA-512 support")
        for password in self.PASSWORDS:
            with self.subTest(password=password):
                hashed = self.api["hash_ztp_password"](password)
                self.assertEqual(crypt.crypt(password, hashed), hashed)


class StoredLineTests(StandInTools):
    """What a save turns the script into."""

    def setUp(self):
        super().setUp()
        self.install_fake_openssl()

    def store(self, content):
        with self.path_first():
            return self.api["hash_ztp_password_lines"](content)

    def test_a_new_password_is_stored_as_a_chpasswd_e_hash(self):
        password = "N3w $Pass it's"
        before = saved_script(legacy_line(password))
        after = self.store(before)
        self.assertNotIn(password, after)
        self.assertNotIn("N3w", after)
        self.assertEqual((self.root / "stdin").read_bytes(),
                         password.encode() + b"\n")
        self.assertIn(f"\n        {hashed_line(self.reply)}\n", after)
        # Nothing but that one line changed, and no line was swallowed.
        changed = [(old, new) for old, new in
                   zip(before.splitlines(), after.splitlines()) if old != new]
        self.assertEqual(changed, [
            ("        " + legacy_line(password),
             "        " + hashed_line(self.reply))])
        self.assertEqual(len(before.splitlines()), len(after.splitlines()))
        self.assertEqual(self.api["validate_ztp_script_content"](after), after)

    def test_a_stored_hash_is_kept_without_calling_the_tool(self):
        # A blank Quick Settings field re-submits the stored line unchanged.
        content = saved_script(hashed_line(canned_hash("K")))
        self.assertEqual(self.store(content), content)
        self.assertEqual(self.openssl_calls(), 0)

    def test_only_the_literal_cumulus_line_is_rewritten(self):
        for line in (
            "echo 'root:OtherAccount1' | chpasswd",
            'echo "cumulus:$SITE_PASSWORD" | chpasswd',
            "echo \"cumulus:$(cat /mnt/secret)\" | chpasswd",
            "echo 'cumulus:' | chpasswd",
            "echo 'cumulus:Kept1' | chpasswd || return 1",
            "# echo 'cumulus:Kept1' | chpasswd",
        ):
            with self.subTest(line=line):
                content = saved_script(hashed_line(canned_hash())) + line + "\n"
                self.assertEqual(self.store(content), content)
        self.assertEqual(self.openssl_calls(), 0)

    def test_the_unquoted_and_double_quoted_legacy_spellings_are_stored_too(self):
        for line in ("echo cumulus:Plain1 | chpasswd",
                     'echo "cumulus:Plain1" | chpasswd',
                     "echo 'cumulus:Plain1'|chpasswd  "):
            with self.subTest(line=line):
                after = self.store(saved_script(hashed_line(canned_hash("Z")))
                                   + line + "\n")
                self.assertNotIn("Plain1", after)
                self.assertTrue(after.endswith(hashed_line(self.reply) + "\n"))
                self.assertEqual((self.root / "stdin").read_bytes(), b"Plain1\n")

    def test_a_hashing_failure_stops_the_save_instead_of_keeping_clear_text(self):
        self.install_fake_openssl(status=1)
        with self.assertRaisesRegex(ValueError, "Could not hash"):
            self.store(saved_script(legacy_line("Simple1")))

    def test_a_clear_text_value_left_with_chpasswd_e_is_refused(self):
        # The editor shows the hashed line; typing a new password over the
        # hash leaves "-e" in place. A switch would install that text as the
        # hash (no password works any more) and it would be served in clear.
        for line in ("echo 'cumulus:NewPass1' | chpasswd -e",
                     "echo cumulus:NewPass1 | chpasswd -e",
                     'echo "cumulus:NewPass1" | chpasswd -e',
                     "echo 'cumulus:NewPass1'|chpasswd  -e  ",
                     "echo 'cumulus:New$Pass1' | chpasswd -e",
                     "echo 'cumulus:$6$<salt>$<hash>' | chpasswd -e",
                     "echo 'cumulus:!' | chpasswd -e",
                     "echo 'cumulus:' | chpasswd -e"):
            with self.subTest(line=line):
                with self.assertRaisesRegex(ValueError, "needs a crypt hash") \
                        as failure:
                    self.store(saved_script(line))
                self.assertNotIn("NewPass1", str(failure.exception))
                self.assertIn("remove -e", str(failure.exception))
        self.assertEqual(self.openssl_calls(), 0)

    def test_hashes_and_unmanaged_lines_with_chpasswd_e_are_still_kept(self):
        for line in (
            hashed_line("$6$rounds=10000$saltstringsaltst$" + "a" * 86),
            hashed_line("$y$j9T$F5Jx5fExrKuPp53xLKQ..1$" + "b" * 43),
            hashed_line("$5$saltsalt$" + "c" * 43),
            'echo "cumulus:\\$6\\$saltsalt\\$' + "d" * 86 + '" | chpasswd -e',
            "echo 'root:OtherAccount1' | chpasswd -e",
            'echo "cumulus:$SITE_HASH" | chpasswd -e',
            "echo 'cumulus:Kept1' | chpasswd -e || return 1",
            "# echo 'cumulus:Kept1' | chpasswd -e",
        ):
            with self.subTest(line=line):
                content = saved_script(line)
                self.assertEqual(self.store(content), content)
        self.assertEqual(self.openssl_calls(), 0)


class OnSwitchExecutionTests(StandInTools):
    """Run the stored shell the way a switch would, with recorded tools."""

    def setUp(self):
        super().setUp()
        for name in ("passwd", "chpasswd"):
            self.write_tool(name, "\n".join((
                f'printf "%s\\n" "{name} $*" >> '
                f'{shlex.quote(str(self.root / "trace"))}',
                f'[ "{name}" = chpasswd ] && cat > '
                f'{shlex.quote(str(self.root / "chpasswd-stdin"))}',
                "exit 0",
            )))

    def run_bash(self, script):
        with self.path_first():
            return subprocess.run(["bash", "-c", script], capture_output=True,
                                  text=True, timeout=30)

    def test_the_ztp_function_hands_chpasswd_the_exact_hash(self):
        # Every "$" of the hash must survive: single quotes, no expansion.
        hashed = canned_hash("Q")
        script = saved_script(hashed_line(hashed))
        function = re.search(r"^function set_password\(\)\{\n.*?^\}\n", script,
                             re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(function)
        result = self.run_bash("set -u\nHOME=/nonexistent\n" + function.group(0)
                               + "set_password\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "trace").read_text().splitlines(),
                         ["passwd -x 99999 cumulus", "chpasswd -e"])
        self.assertEqual((self.root / "chpasswd-stdin").read_text(),
                         f"cumulus:{hashed}\n")

    def test_the_legacy_function_still_runs_untouched(self):
        script = saved_script(legacy_line("Old $Pass"))
        function = re.search(r"^function set_password\(\)\{\n.*?^\}\n", script,
                             re.MULTILINE | re.DOTALL)
        result = self.run_bash(function.group(0) + "set_password\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "trace").read_text().splitlines(),
                         ["passwd -x 99999 cumulus", "chpasswd "])
        self.assertEqual((self.root / "chpasswd-stdin").read_text(),
                         "cumulus:Old $Pass\n")

    def test_the_upgrade_hook_hands_chpasswd_the_exact_hash(self):
        hashed = canned_hash("H")
        hook = self.api["prepare_upgrade_post_install_script"](
            saved_script(hashed_line(hashed)), "192.0.2.250")
        for name in ("chown", "visudo"):
            self.write_tool(name, "exit 0")
        (self.root / "etc/sudoers.d").mkdir(parents=True)
        hook = hook.replace("/etc/sudoers.d/", str(self.root / "etc/sudoers.d") + "/")
        hook = hook.replace("/root/.ssh", str(self.root / "root/.ssh"))
        hook = hook.replace("/home/cumulus/.ssh", str(self.root / "home/.ssh"))
        path = self.root / "hook.sh"
        path.write_text(hook, encoding="utf-8")
        with self.path_first():
            result = subprocess.run(["bash", str(path)], capture_output=True,
                                    text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "trace").read_text().splitlines(),
                         ["passwd -x 99999 cumulus", "chpasswd -e"])
        self.assertEqual((self.root / "chpasswd-stdin").read_text(),
                         f"cumulus:{hashed}\n")
        self.assertNotIn(hashed, result.stdout + result.stderr)


class UpgradeHookBothFormsTests(unittest.TestCase):
    SERVER = "[2001:db8::250]:8080"

    def setUp(self):
        self.api = load_api()

    def prepare(self, script):
        return self.api["prepare_upgrade_post_install_script"](script, self.SERVER)

    def test_a_legacy_script_still_yields_the_version_1_hook(self):
        password = "It's a $password `literal` \\ value"
        hook = self.prepare(saved_script(legacy_line(password)))
        self.assertIn(PREVIOUS_HOOK_MARKER, hook)
        self.assertEqual(
            self.api["upgrade_literal_assignment"](hook, "CUMULUS_PASSWORD"),
            password)
        self.assertIn('"cumulus:$CUMULUS_PASSWORD" | chpasswd; then', hook)
        self.assertNotIn("chpasswd -e", hook)
        self.assertEqual(self.api["validate_upgrade_preserve_hook_content"](hook),
                         hook)
        # Byte-for-byte what 4.2.x renders for the same settings: a job pinned
        # before or after a rollback stays valid on both images.
        self.assertEqual(
            hashlib.sha256(hook.encode("utf-8")).hexdigest(),
            "c692f786d7ee0f3f89c8e9da75dd01b6b553d706a3ba30406168d9e0502a15f5")

    def test_a_hashed_script_yields_the_version_2_hook(self):
        hashed = canned_hash("V")
        hook = self.prepare(saved_script(hashed_line(hashed)))
        self.assertIn("\n# LLDPQ_UPGRADE_HOOK_VERSION=2\n", hook)
        self.assertNotIn(PREVIOUS_HOOK_MARKER, hook)
        self.assertEqual(
            self.api["upgrade_literal_assignment"](hook, "CUMULUS_PASSWORD_HASH"),
            hashed)
        self.assertNotRegex(hook, r"(?m)^\s*CUMULUS_PASSWORD=")
        self.assertIn('"cumulus:$CUMULUS_PASSWORD_HASH" | chpasswd -e; then', hook)
        self.assertEqual(self.api["validate_upgrade_preserve_hook_content"](hook),
                         hook)
        self.assertEqual(self.api["validate_ztp_script_content"](hook), hook)
        self.assertEqual(
            self.api["upgrade_literal_assignment"](hook, "IMAGE_SERVER_HOSTNAME"),
            self.SERVER)

    def test_older_template_versions_are_read_in_both_forms(self):
        for version in (2, 3, 4):
            for line, marker in (
                    (legacy_line("Simple1"), "VERSION=1"),
                    (hashed_line(canned_hash()), "VERSION=2")):
                with self.subTest(version=version, marker=marker):
                    hook = self.prepare(saved_script(line, version=version))
                    self.assertIn("LLDPQ_UPGRADE_HOOK_" + marker + "\n", hook)

    def test_other_crypt_schemes_an_administrator_pasted_are_accepted(self):
        for hashed in ("$6$rounds=10000$saltstringsaltst$" + "a" * 86,
                       "$y$j9T$F5Jx5fExrKuPp53xLKQ..1$" + "b" * 43,
                       "$5$saltsalt$" + "c" * 43):
            with self.subTest(hashed=hashed):
                hook = self.prepare(saved_script(hashed_line(hashed)))
                self.assertEqual(self.api["upgrade_literal_assignment"](
                    hook, "CUMULUS_PASSWORD_HASH"), hashed)
                self.api["validate_upgrade_preserve_hook_content"](hook)

    def test_a_clear_text_value_marked_as_hash_cannot_start_an_upgrade(self):
        # "chpasswd -e" with a plain password would lock the account out.
        for payload in ("PlainPassword1", "Plain$Password", "", "!"):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    self.prepare(saved_script(hashed_line(payload)))

    def test_two_password_lines_are_ambiguous_in_any_mix(self):
        for extra in (legacy_line("Other1"), hashed_line(canned_hash("B"))):
            for first in (legacy_line("Simple1"), hashed_line(canned_hash())):
                with self.subTest(first=first, extra=extra):
                    with self.assertRaisesRegex(ValueError, "one literal cumulus"):
                        self.prepare(saved_script(first) + "\n" + extra + "\n")

    def test_the_validator_rejects_a_tampered_or_mixed_hook(self):
        hashed = canned_hash()
        hook = self.prepare(saved_script(hashed_line(hashed)))
        legacy = self.prepare(saved_script(legacy_line("Simple1")))
        for changed in (
            hook.replace("chpasswd -e", "chpasswd"),
            hook.replace("umask 077", "umask 077; nv config replace evil.yaml"),
            hook + "\ncurl http://unavailable/config.yaml\n",
            # A clear-text hook relabelled as version 2, and the reverse.
            legacy.replace("HOOK_VERSION=1", "HOOK_VERSION=2"),
            hook.replace("HOOK_VERSION=2", "HOOK_VERSION=1"),
            hook.replace(hashed, "PlainPassword1"),
        ):
            with self.subTest(changed=changed[-80:]):
                with self.assertRaises(ValueError):
                    self.api["validate_upgrade_preserve_hook_content"](changed)

    def test_the_shipped_template_is_readable_once_its_settings_are_filled(self):
        filled = ZTP_TEMPLATE.replace("__TARGET_OS_VERSION__", "5.16.0").replace(
            "__IMAGE_SERVER_IP__", "192.0.2.250").replace(
                'KEY=""', "KEY=" + shlex.quote(KEY))
        hook = self.prepare(filled)
        self.assertRegex(hook, r"\n# LLDPQ_UPGRADE_HOOK_VERSION=[12]\n")
        self.assertEqual(self.api["validate_upgrade_preserve_hook_content"](hook),
                         hook)


class PreviousReleaseFailsClosedTests(unittest.TestCase):
    """What a rolled-back 4.2.x image does with a script this version saved."""

    def setUp(self):
        self.script = saved_script(hashed_line(canned_hash()))

    def test_the_previous_parsers_do_not_read_a_hash_as_a_password(self):
        # A match would make 4.2.x show the hash as the password and write
        # "echo 'cumulus:<hash>' | chpasswd": a switch nobody can log in to.
        for pattern in (PREVIOUS_API_PASSWORD_LINE, PREVIOUS_UI_PASSWORD_LINE):
            with self.subTest(pattern=pattern):
                self.assertEqual(
                    re.findall(pattern, self.script, re.MULTILINE), [])

    def test_the_previous_parsers_still_read_the_legacy_form(self):
        legacy = saved_script(legacy_line("Simple1"))
        for pattern in (PREVIOUS_API_PASSWORD_LINE, PREVIOUS_UI_PASSWORD_LINE):
            with self.subTest(pattern=pattern):
                self.assertEqual(
                    len(re.findall(pattern, legacy, re.MULTILINE)), 1)

    def test_the_previous_hook_validator_does_not_accept_a_version_2_hook(self):
        api = load_api()
        hook = api["prepare_upgrade_post_install_script"](
            self.script, "192.0.2.250")
        self.assertNotIn(PREVIOUS_HOOK_MARKER, hook)
        self.assertNotRegex(hook, r"(?m)^\s*CUMULUS_PASSWORD=")


class SaveActionTests(StandInTools):
    def setUp(self):
        super().setUp()
        self.install_fake_openssl()
        self.written = []
        self.api = load_api(
            ZTP_SCRIPT_FILE=str(self.root / "cumulus-ztp.sh"),
            write_managed_text=lambda path, content, mode=0o664:
                self.written.append((path, content, mode)),
            bind_ztp_image_name=lambda content: content,
            valid_os_image_name=lambda name: False,
            ensure_provision_root_link=lambda name: None,
        )

    def save(self, content):
        self.api["POST_DATA"] = json.dumps({"content": content})
        with self.path_first():
            with self.assertRaises(Emitted) as response:
                self.api["action_save_ztp_script"]()
        return response.exception.payload

    def test_saving_a_legacy_script_stores_and_returns_the_hash(self):
        password = "Adm1n $ecret"
        payload = self.save(saved_script(legacy_line(password)))
        self.assertTrue(payload["success"], payload)
        (path, stored, mode), = self.written
        self.assertEqual(path, str(self.root / "cumulus-ztp.sh"))
        self.assertEqual(mode, 0o775)
        self.assertNotIn(password, stored)
        self.assertEqual(HASH_LINE.findall(stored), [("        ", self.reply)])
        # The page replaces its editor with this, so it must be what is served.
        self.assertEqual(payload["content"], stored)
        self.assertNotIn(password, json.dumps(payload))

    def test_saving_the_stored_script_again_changes_nothing(self):
        stored = saved_script(hashed_line(canned_hash("S")))
        payload = self.save(stored)
        self.assertTrue(payload["success"], payload)
        self.assertEqual(self.written[0][1], stored)
        self.assertEqual(self.openssl_calls(), 0)

    def test_a_script_is_not_saved_when_the_password_cannot_be_hashed(self):
        self.install_fake_openssl(status=1)
        password = "Adm1n $ecret"
        payload = self.save(saved_script(legacy_line(password)))
        self.assertFalse(payload["success"])
        self.assertEqual(payload["error_code"], "invalid_ztp_script")
        self.assertIn("Could not hash the cumulus password", payload["error"])
        self.assertNotIn(password, json.dumps(payload))
        self.assertEqual(self.written, [])

    def test_a_clear_text_password_left_with_chpasswd_e_is_not_saved(self):
        # Reported "saved" before, with the page showing "stored as a hash".
        password = "NewPass1"
        content = saved_script(hashed_line(password))
        payload = self.save(content)
        self.assertFalse(payload["success"])
        self.assertEqual(payload["error_code"], "invalid_ztp_script")
        self.assertTrue(payload["error"].startswith(
            'ZTP script was not saved: "chpasswd -e" needs a crypt hash'),
            payload["error"])
        self.assertNotIn(password, json.dumps(payload))
        self.assertEqual(self.written, [])
        self.assertEqual(self.openssl_calls(), 0)
        # The save now refuses exactly what a device upgrade already refused.
        with self.assertRaisesRegex(ValueError, "Invalid cumulus password hash"):
            self.api["prepare_upgrade_post_install_script"](content, "192.0.2.250")
        # Dropping "-e", as the message says, stores the password as a hash.
        payload = self.save(saved_script(legacy_line(password)))
        self.assertTrue(payload["success"], payload)
        self.assertEqual(HASH_LINE.findall(self.written[0][1]),
                         [("        ", self.reply)])

    def test_every_hash_form_the_save_keeps_can_start_a_device_upgrade(self):
        for hashed in (canned_hash("S"),
                       "$6$rounds=10000$saltstringsaltst$" + "a" * 86,
                       "$y$j9T$F5Jx5fExrKuPp53xLKQ..1$" + "b" * 43):
            with self.subTest(hashed=hashed):
                self.written.clear()
                stored = saved_script(hashed_line(hashed))
                payload = self.save(stored)
                self.assertTrue(payload["success"], payload)
                self.assertEqual(self.written[0][1], stored)
                hook = self.api["prepare_upgrade_post_install_script"](
                    payload["content"], "192.0.2.250")
                self.assertEqual(self.api["upgrade_literal_assignment"](
                    hook, "CUMULUS_PASSWORD_HASH"), hashed)
        self.assertEqual(self.openssl_calls(), 0)

    @unittest.skipUnless(REAL_OPENSSL, "this openssl has no 'passwd -6'")
    def test_end_to_end_the_stored_hash_verifies_against_the_typed_password(self):
        real = shutil.which("openssl")
        (self.bin / "openssl").unlink()
        self.assertIsNotNone(real)
        password = "it's $HOME `id` ✓"
        payload = self.save(saved_script(legacy_line(password)))
        self.assertTrue(payload["success"], payload)
        (_, hashed), = HASH_LINE.findall(payload["content"])
        self.assertTrue(verifies(password, hashed))
        # ...and the device-upgrade hook built from it carries the same hash.
        hook = self.api["prepare_upgrade_post_install_script"](
            payload["content"], "192.0.2.250")
        self.assertEqual(self.api["upgrade_literal_assignment"](
            hook, "CUMULUS_PASSWORD_HASH"), hashed)


if __name__ == "__main__":
    unittest.main()
