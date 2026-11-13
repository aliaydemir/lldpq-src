"""What docker/docker-build.sh leaves next to the image archive and prints.

The guide tells operators to verify a published SHA-256 before loading the
archive, so the build writes one next to it (sha256sum, or shasum where that is
missing).  The closing lines point at the guide's Quick start instead of a
`docker run` line that fits no documented deployment, and remind the releaser
of the one check that needs a Cumulus switch.  The copy hint among them names
the checksum file with the archive, so the pair travels together.

Only this script knows the release: it passes the VERSION file to the image's
version label.  The Dockerfile's own default, which every other build gets
(`docker compose build`), used to name one old release, 4.0.4.

The build itself needs Docker; the checksum step and the copy hint are cut out
of the script and run for real, the rest is pinned as text.
"""

from pathlib import Path
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = (ROOT / 'docker/docker-build.sh').read_text()
DOCKERFILE = (ROOT / 'docker/Dockerfile').read_text()
DOCKER_DOC = (ROOT / 'DOCKER.md').read_text()

# From the checksum file's name to the end of the `if` that writes it.
CHECKSUM_STEP = re.search(r'(?ms)^CHECKSUM_FILE="\$\{OUTPUT_FILE\}\.sha256"\n.*?^fi\n',
                          BUILD_SCRIPT)
# The `if` that prints the copy hint, with or without the checksum file.
UPLOAD_HINT = re.search(r'(?ms)^if \[ -n "\$\{CHECKSUM_FILE\}" \]; then\n'
                        r'[^\n]*"Upload: .*?^fi\n', BUILD_SCRIPT)
ARCHIVE = b'not really a docker image\n' * 64
DIGEST = hashlib.sha256(ARCHIVE).hexdigest()


class ChecksumStepTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(CHECKSUM_STEP, 'the checksum step is missing from docker-build.sh')
        self._tmp = tempfile.TemporaryDirectory(prefix='lldpq-build-')
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.archive = self.root / 'out' / 'lldpq-amd64.tar.gz'
        self.archive.parent.mkdir()
        self.archive.write_bytes(ARCHIVE)
        self.checksum = Path(f'{self.archive}.sha256')

    def tools(self, **stand_ins):
        """A PATH with only what the step needs, plus the given stand-ins."""
        directory = self.root / 'tools'
        directory.mkdir()
        for name in ('dirname', 'basename', 'chmod', 'rm'):
            (directory / name).symlink_to(shutil.which(name))
        for name, body in stand_ins.items():
            path = directory / name
            path.write_text(body)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(directory)

    def run_step(self, path=None):
        # The script's own strict mode: a failing checksum must not stop it.
        source = ('set -euo pipefail\nGREEN= YELLOW= NC=\n'
                  f'OUTPUT_FILE="$1"\n{CHECKSUM_STEP.group(0)}'
                  'echo "CONTINUED CHECKSUM_FILE=<${CHECKSUM_FILE}>"\n')
        env = dict(os.environ)
        if path is not None:
            env['PATH'] = path
        result = subprocess.run(
            [shutil.which('bash'), '-c', source, 'docker-build.sh', str(self.archive)],
            capture_output=True, text=True, timeout=20, env=env, cwd=self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_checksum_is_written_next_to_the_archive(self):
        result = self.run_step()
        self.assertEqual(result.stdout,
                         f'  ✓ SHA-256 written to {self.checksum}\n'
                         f'CONTINUED CHECKSUM_FILE=<{self.checksum}>\n')
        # The bare file name, so the pair verifies wherever it is downloaded to.
        self.assertEqual(self.checksum.read_text(), f'{DIGEST}  lldpq-amd64.tar.gz\n')
        self.assertEqual(stat.S_IMODE(self.checksum.stat().st_mode), 0o644)
        self.assertEqual(self.archive.read_bytes(), ARCHIVE)

    def test_published_pair_verifies_in_another_directory(self):
        self.run_step()
        elsewhere = self.root / 'downloads'
        elsewhere.mkdir()
        for path in (self.archive, self.checksum):
            shutil.copy(path, elsewhere / path.name)
        verify = (['sha256sum', '-c'] if shutil.which('sha256sum')
                  else ['shasum', '-a', '256', '-c'])
        result = subprocess.run([*verify, self.checksum.name], cwd=elsewhere,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual((result.returncode, result.stdout),
                         (0, 'lldpq-amd64.tar.gz: OK\n'), result.stderr)

    def test_shasum_is_used_where_sha256sum_is_missing(self):
        path = self.tools(shasum='#!/bin/bash\n'
                                 'printf \'%s\\n\' "$*" > "$(dirname "$0")/shasum.args"\n'
                                 'echo "from-shasum  $3"\n')
        result = self.run_step(path)
        self.assertIn('✓ SHA-256 written', result.stdout)
        self.assertEqual((self.root / 'tools/shasum.args').read_text(),
                         '-a 256 lldpq-amd64.tar.gz\n')
        self.assertEqual(self.checksum.read_text(), 'from-shasum  lldpq-amd64.tar.gz\n')

    def test_sha256sum_is_preferred(self):
        path = self.tools(sha256sum='#!/bin/bash\necho "from-sha256sum  $1"\n',
                          shasum='#!/bin/bash\necho "from-shasum  $3"\n')
        self.run_step(path)
        self.assertEqual(self.checksum.read_text(), 'from-sha256sum  lldpq-amd64.tar.gz\n')

    def test_build_carries_on_without_a_checksum_tool(self):
        for name, tools in (('neither tool', {}),
                            ('failing tool', {'sha256sum': '#!/bin/bash\necho partial\nexit 1\n'})):
            with self.subTest(name):
                shutil.rmtree(self.root / 'tools', ignore_errors=True)
                result = self.run_step(self.tools(**tools))
                self.assertEqual(
                    result.stdout,
                    '  ⚠ SHA-256 not written (neither sha256sum nor shasum worked)\n'
                    'CONTINUED CHECKSUM_FILE=<>\n')
                # No half-written checksum is left to be published.
                self.assertFalse(self.checksum.exists())
                self.assertEqual(self.archive.read_bytes(), ARCHIVE)


class UploadHintTests(unittest.TestCase):
    def hint(self, checksum_file):
        self.assertIsNotNone(UPLOAD_HINT, 'the copy hint is missing from docker-build.sh')
        source = ('set -euo pipefail\nYELLOW= NC=\nARCH_LABEL=amd64\n'
                  f'CHECKSUM_FILE="$1"\n{UPLOAD_HINT.group(0)}')
        result = subprocess.run(
            [shutil.which('bash'), '-c', source, 'docker-build.sh', checksum_file],
            capture_output=True, text=True, timeout=20)
        self.assertEqual((result.returncode, result.stderr), (0, ''))
        return result.stdout

    def test_checksum_file_is_copied_with_the_archive(self):
        self.assertEqual(
            self.hint('/home/builder/lldpq-amd64.tar.gz.sha256'),
            'Upload: scp ~/lldpq-amd64.tar.gz ~/lldpq-amd64.tar.gz.sha256 user@host:~/\n')

    def test_hint_names_no_checksum_file_when_none_was_written(self):
        # The checksum step empties CHECKSUM_FILE then; scp would stop at a
        # file that does not exist.
        self.assertEqual(self.hint(''), 'Upload: scp ~/lldpq-amd64.tar.gz user@host:~/\n')

    def test_hint_names_the_two_files_the_build_writes(self):
        # ~ in the hint is $HOME in the script, and the names are the same.
        self.assertIn('OUTPUT_FILE="$HOME/lldpq-${ARCH_LABEL}.tar.gz"\n', BUILD_SCRIPT)
        self.assertIn('CHECKSUM_FILE="${OUTPUT_FILE}.sha256"\n', BUILD_SCRIPT)
        self.assertEqual(BUILD_SCRIPT.count('"Upload: '), 2)
        # Printed after the summary and before the load line, as it was.
        hint = BUILD_SCRIPT.index(UPLOAD_HINT.group(0))
        self.assertLess(BUILD_SCRIPT.index('|| echo -e "SHA256: '), hint)
        self.assertLess(hint, BUILD_SCRIPT.index('echo -e "Load:   '))


class VersionLabelTests(unittest.TestCase):
    def test_default_names_no_release(self):
        self.assertEqual(re.findall(r'(?m)^ARG LLDPQ_VERSION\b.*$', DOCKERFILE),
                         ['ARG LLDPQ_VERSION=unknown'])
        self.assertIn('\nLABEL version="${LLDPQ_VERSION}"\n', DOCKERFILE)
        # The argument is declared before the label that uses it.
        self.assertLess(DOCKERFILE.index('\nARG LLDPQ_VERSION='),
                        DOCKERFILE.index('\nLABEL version='))

    def test_build_script_passes_the_version_file(self):
        self.assertIn('VERSION=$(cat "$REPO_ROOT/VERSION" 2>/dev/null || echo "dev")\n',
                      BUILD_SCRIPT)
        self.assertIn('    --build-arg LLDPQ_VERSION="${VERSION}" \\\n', BUILD_SCRIPT)


class BuildScriptTextTests(unittest.TestCase):
    def test_checksum_follows_the_export_and_is_named_in_the_summary(self):
        export = BUILD_SCRIPT.index('sudo docker save ${IMAGE_NAME}:${IMAGE_TAG} | gzip > "${OUTPUT_FILE}"')
        step = BUILD_SCRIPT.index(CHECKSUM_STEP.group(0))
        summary = BUILD_SCRIPT.index('[ -z "${CHECKSUM_FILE}" ] || echo -e "SHA256: ')
        self.assertLess(export, step)
        self.assertLess(step, summary)
        self.assertLess(BUILD_SCRIPT.index('echo -e "File:   ${CYAN}${OUTPUT_FILE}${NC}"'), summary)

    def test_closing_lines_point_at_the_guide_not_at_a_bare_docker_run(self):
        self.assertNotIn('docker run', BUILD_SCRIPT)
        self.assertIn('echo -e "Run:    ${YELLOW}see \\"Quick start\\" in DOCKER.md${NC}"\n',
                      BUILD_SCRIPT)
        self.assertIn('\n## Quick start\n', DOCKER_DOC)

    def test_release_reminder_names_the_switch_check_on_one_line(self):
        reminder = [line for line in BUILD_SCRIPT.splitlines()
                    if 'test-mgmt-vrf-switch.sh' in line]
        self.assertEqual(len(reminder), 1)
        self.assertTrue(reminder[0].startswith('echo -e "Release: '), reminder[0])
        self.assertIn('on a Cumulus switch', reminder[0])
        self.assertIn('sudo bash docker/test-mgmt-vrf-switch.sh', reminder[0])
        # It is the last thing printed, where it is read.
        self.assertEqual(BUILD_SCRIPT.rstrip().splitlines()[-1], reminder[0])

    def test_nothing_new_stops_a_build(self):
        # The only exit is the missing-Docker check that was always there.
        self.assertEqual(re.findall(r'(?m)^\s*exit \d+', BUILD_SCRIPT), ['    exit 1'])
        self.assertNotIn('git status', BUILD_SCRIPT)


if __name__ == '__main__':
    unittest.main()
