#!/usr/bin/env python3
"""No sample file under lldpq/ may carry a real-looking NetQ key pair.

lldpq/commands is the list of example commands `send-cmd` reads; it is tracked
and copied into every image. One commented example,

    #sudo netq config add cli server ... access-key <value> secret-key <value> ...

held what looks like a real access-key / secret-key pair instead of
placeholders, so everyone with the repository or the image had it.

A failure names the file, the line and the keyword only - never the value.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_DIR = ROOT / "lldpq"

# A placeholder such as <access-key> starts with "<" and is not matched.
KEY_VALUE = re.compile(
    r"""(access-key|secret-key)[\s=:"']+[A-Za-z0-9+/_-]{20,}""", re.IGNORECASE
)


def _sample_files() -> list[Path]:
    """Tracked files below lldpq/, plus new ones git would add.

    Outside a git checkout every file below lldpq/ is taken instead.
    """
    try:
        listed = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
             "--", "lldpq"],
            cwd=ROOT, capture_output=True, check=True, timeout=60,
        ).stdout.decode("utf-8", "surrogateescape").split("\0")
        paths = [ROOT / name for name in listed if name]
    except (OSError, subprocess.SubprocessError):
        paths = []
    if not paths:
        paths = [path for path in SAMPLE_DIR.rglob("*")
                 if "__pycache__" not in path.parts]
    return sorted(path for path in paths if path.is_file())


def _findings(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return [
        f"{path.relative_to(ROOT)}:{number} ({match.group(1).lower()})"
        for number, line in enumerate(text.splitlines(), 1)
        for match in KEY_VALUE.finditer(line)
    ]


def _netq_example() -> tuple[int, bool, bool]:
    """(number of NetQ examples, all commented, all with placeholders).

    Only these facts leave the function, so a failure cannot show the line.
    """
    examples = [
        line
        for line in (SAMPLE_DIR / "commands").read_text(encoding="utf-8").splitlines()
        if "netq config add cli server" in line
    ]
    return (
        len(examples),
        all(line.startswith("#") for line in examples),
        all(" access-key <access-key> secret-key <secret-key> " in line
            for line in examples),
    )


class SampleKeyTests(unittest.TestCase):
    def test_the_check_sees_the_shipped_samples(self):
        self.assertIn(SAMPLE_DIR / "commands", _sample_files())

    def test_the_check_recognises_a_key_and_ignores_a_placeholder(self):
        # Built here so that this file never matches itself.
        hex_key = "0123456789abcdef" * 4
        base64_key = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo" + "wMTIzNDU2Nzg="
        line = f"netq config add cli server 192.0.2.1 access-key {hex_key} secret-key {base64_key} premises P"
        self.assertEqual(
            [match.group(1) for match in KEY_VALUE.finditer(line)],
            ["access-key", "secret-key"],
        )
        self.assertIsNone(
            KEY_VALUE.search("access-key <access-key> secret-key <secret-key> premises P")
        )
        self.assertIsNone(KEY_VALUE.search("--access-key  --secret-key  short1234"))

    def test_no_sample_file_carries_a_key_value(self):
        findings = [finding for path in _sample_files() for finding in _findings(path)]
        self.assertEqual(findings, [], "key-like value after access-key/secret-key")

    def test_the_netq_example_keeps_its_placeholders(self):
        count, commented, placeholders = _netq_example()
        self.assertEqual(count, 1)
        self.assertTrue(commented, "the NetQ example is no longer a comment")
        self.assertTrue(placeholders, "the NetQ example no longer uses the placeholders")


if __name__ == "__main__":
    unittest.main()
