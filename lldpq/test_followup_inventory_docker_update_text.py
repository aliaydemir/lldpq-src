"""In a Docker deployment the update actions answer in the words of the page.

A container cannot replace its own image, so html/setup-api.sh refuses "update"
and "update-offline" there.  Its message still named one command pair
("docker load + docker compose up") and "the instructions on this page", while
the page and the update popup now send the operator to the Updating section of
DOCKER.md: that command pair leaves a container created with `docker run`
running on the old image.

The two handlers are cut out of setup-api.sh and run as inside a container.
"""

import ast
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'html/setup-api.sh').read_text().split(
    "python3 << 'PYTHON'\n", 1)[1].rsplit('\nPYTHON', 1)[0]
MESSAGE = ('Docker deployment: update on the host that runs the container, '
           'with the steps under Updating in DOCKER.md.')
GUIDE = 'https://github.com/aliaydemir/lldpq-src/blob/main/DOCKER.md#updating'


def handler(action):
    for node in ast.parse(SOURCE).body:
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name) and node.test.left.id == 'action'
                and ast.literal_eval(node.test.comparators[0]) == action):
            return compile(ast.Module(body=[node], type_ignores=[]), f'setup-{action}', 'exec')
    raise AssertionError(f'no handler for {action}')


class DockerUpdateTextTests(unittest.TestCase):
    def answer(self, action, body):
        cleaned = []
        namespace = {'action': action, 'post_data': body, 'json': json, 'sys': sys, 'os': os,
                     'cleanup_uploaded_tarball': cleaned.append}
        exists = os.path.exists
        output = io.StringIO()
        with mock.patch('os.path.exists',
                        side_effect=lambda path: path == '/.dockerenv' or exists(path)), \
                redirect_stdout(output), self.assertRaises(SystemExit) as stopped:
            exec(handler(action), namespace)
        self.assertEqual(stopped.exception.code, 0)
        return json.loads(output.getvalue()), cleaned

    def test_update_is_refused_with_a_pointer_to_the_guide(self):
        answer, _ = self.answer('update', {})
        self.assertEqual(answer, {'success': False, 'docker': True, 'error': MESSAGE})

    def test_offline_update_is_refused_the_same_way_and_drops_the_upload(self):
        answer, cleaned = self.answer('update-offline', {'path': '/tmp/lldpq-upload-src.x.tar.gz'})
        self.assertEqual(answer, {'success': False, 'docker': True, 'error': MESSAGE})
        self.assertEqual(cleaned, ['/tmp/lldpq-upload-src.x.tar.gz'])

    def test_message_is_one_sentence_and_names_no_command(self):
        self.assertEqual(SOURCE.count(MESSAGE), 2)
        self.assertNotIn('. ', MESSAGE)
        for old in ('docker load', 'compose', 'this page'):
            self.assertNotIn(old, MESSAGE)
        # The section it names is the one the page and the popup link to.
        for page in ('html/setup.html', 'html/index.html'):
            self.assertIn(GUIDE, (ROOT / page).read_text(), page)


if __name__ == '__main__':
    unittest.main()
