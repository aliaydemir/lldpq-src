#!/usr/bin/env python3
"""Keeps a stored OS image reachable at the URL ZTP and ONIE actually fetch.

Uploads are stored in WEB_ROOT/provision-uploads/ and published at the
historical web-root URL as a relative symlink, because cumulus-ztp.sh hands
onie-install `http://<image server>/<image name>`.  Publishing happened only
inside the upload transaction: the Docker entrypoint rebuilds every link at
container start, but a native install had nothing that reconciled them.  An
image copied in by hand, or one whose link was lost, therefore stayed listed
and bindable in Provision while its URL answered 404 -- a failure that only
surfaced once onie-install ran on the switch.

Pinned here: the listing reports reachability instead of mere storage, the
read paths restore a lost link, a legacy image kept directly in the web root
is never replaced, and the installer performs the same reconciliation the
Docker entrypoint does.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "install.sh"
PROVISION_API = (ROOT / "html" / "provision-api.sh").read_text(encoding="utf-8")
PROVISION_HTML = (ROOT / "html" / "provision.html").read_text(encoding="utf-8")
DOCKER_ENTRYPOINT = (ROOT / "docker" / "docker-entrypoint.sh").read_text(
    encoding="utf-8")

_BODY = PROVISION_API[
    PROVISION_API.index("python3 << 'PYTHON_SCRIPT'\n"):
    PROVISION_API.rindex("\nPYTHON_SCRIPT\n")
]
_TREE = ast.parse(_BODY)

# In dependency order.
IMAGE_LINK_NAMES = (
    'image_version_from_name', 'valid_os_image_name',
    'publish_provision_root_link', 'provision_root_link_state',
    'ensure_provision_root_link', 'reconcile_provision_root_links',
    'list_os_image_objects',
)

IMAGE = "cumulus-linux-5.9.2-mlnx-amd64.bin"


def extract_source(name: str) -> str:
    """Slice one top-level def out of the CGI's embedded Python."""
    for node in _TREE.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            start = min([node.lineno] +
                        [decorator.lineno for decorator in node.decorator_list])
            return "\n".join(_BODY.splitlines()[start - 1:node.end_lineno]) + "\n"
    raise AssertionError(f"{name} not found in provision-api.sh")


class ProvisionImageWebLinkTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.web_root = Path(self._tmp.name) / "html"
        self.upload_dir = self.web_root / "provision-uploads"
        self.upload_dir.mkdir(parents=True)

        namespace = {
            "os": os, "re": re, "shlex": shlex, "subprocess": subprocess,
            "PROVISION_UPLOAD_DIR": str(self.upload_dir),
            "WEB_ROOT": str(self.web_root),
            "LLDPQ_USER": "lldpq",
        }
        for name in IMAGE_LINK_NAMES:
            exec(compile(extract_source(name), "provision-api.sh", "exec"),
                 namespace)
        self.api = namespace

    # ---------- helpers ----------

    def store(self, name=IMAGE):
        (self.upload_dir / name).write_bytes(b"image")

    def link(self, name=IMAGE):
        return self.web_root / name

    def listed(self, name=IMAGE):
        for image in self.api['list_os_image_objects']():
            if image['name'] == name:
                return image
        return None

    # ---------- the state the customer was found in ----------

    def test_a_stored_image_without_its_link_is_reported_unserved(self):
        """A hand-copied image is listed; it must not look reachable."""
        self.store()
        self.assertEqual(self.api['provision_root_link_state'](IMAGE), 'missing')
        listing = self.api['list_os_image_objects']()
        self.assertEqual([image['name'] for image in listing], [IMAGE])
        self.assertFalse(listing[0]['served'])

    def test_the_read_path_restores_a_lost_link(self):
        self.store()
        self.assertTrue(
            self.api['reconcile_provision_root_links'](
                self.api['list_os_image_objects']()))
        self.assertTrue(self.link().is_symlink())
        self.assertEqual(os.readlink(self.link()), f"provision-uploads/{IMAGE}")
        self.assertTrue(self.listed()['served'])

    def test_reconciliation_is_idempotent_and_reports_no_change(self):
        self.store()
        self.api['ensure_provision_root_link'](IMAGE)
        before = os.lstat(self.link())
        self.assertFalse(
            self.api['reconcile_provision_root_links'](
                self.api['list_os_image_objects']()))
        self.assertEqual(os.lstat(self.link()).st_ino, before.st_ino)

    def test_a_link_pointing_at_another_copy_is_corrected(self):
        self.store()
        self.link().symlink_to("elsewhere/" + IMAGE)
        self.assertEqual(self.api['provision_root_link_state'](IMAGE), 'foreign')
        self.assertTrue(self.api['ensure_provision_root_link'](IMAGE))
        self.assertEqual(os.readlink(self.link()), f"provision-uploads/{IMAGE}")

    # ---------- the legacy layout must survive ----------

    def test_an_image_served_from_the_web_root_itself_counts_as_served(self):
        (self.web_root / IMAGE).write_bytes(b"legacy image")
        self.assertEqual(self.api['provision_root_link_state'](IMAGE), 'ok')
        self.assertTrue(self.listed()['served'])

    def test_a_legacy_web_root_copy_is_never_replaced_by_a_link(self):
        """Overwriting it would serve different bytes than the operator put there."""
        self.store()
        (self.web_root / IMAGE).write_bytes(b"legacy image")
        self.api['reconcile_provision_root_links'](
            self.api['list_os_image_objects']())
        self.assertFalse(self.link().is_symlink())
        self.assertEqual(self.link().read_bytes(), b"legacy image")

    def test_a_directory_in_the_way_is_refused_rather_than_removed(self):
        self.store()
        self.link().mkdir()
        self.assertFalse(self.api['ensure_provision_root_link'](IMAGE))
        self.assertTrue(self.link().is_dir())

    # ---------- the publisher must not claim a link it did not create ----------

    def test_a_privileged_fallback_that_produced_no_link_is_not_success(self):
        """The upload transaction trusts this verdict to gate its rollback."""
        self.store()
        os.chmod(self.web_root, 0o500)
        self.addCleanup(os.chmod, self.web_root, 0o755)
        with mock.patch.object(
                subprocess, 'run',
                return_value=subprocess.CompletedProcess([], 0)) as runner:
            self.assertFalse(self.api['publish_provision_root_link'](IMAGE))
        self.assertTrue(runner.called, "the privileged fallback was not attempted")

    def test_an_unstored_name_is_never_published(self):
        self.assertFalse(self.api['publish_provision_root_link'](IMAGE))
        self.assertFalse(self.link().exists())

    def test_a_traversing_name_is_rejected_by_the_state_check(self):
        self.assertEqual(
            self.api['provision_root_link_state']("../../etc/passwd"), 'foreign')

    # ---------- installer parity with the Docker entrypoint ----------

    def run_installer_reconcile(self):
        script = f"""
            set -e
            export LLDPQ_INSTALL_LIB_ONLY=true
            export LLDPQ_TEST_NO_SUDO=true
            source '{INSTALL_SH}'
            LLDPQ_USER="$(id -un)"
            status=0
            republish_provision_image_links '{self.web_root}' || status=$?
            echo "STATUS=$status"
        """
        return subprocess.run(["bash", "-c", script], capture_output=True,
                              text=True, cwd=str(ROOT))

    def test_the_installer_republishes_a_stored_image(self):
        self.store()
        result = self.run_installer_reconcile()
        self.assertIn("STATUS=0", result.stdout,
                      msg=f"stdout={result.stdout}\nstderr={result.stderr}")
        self.assertEqual(os.readlink(self.link()), f"provision-uploads/{IMAGE}")

    def test_the_installer_leaves_a_legacy_web_root_copy_alone(self):
        self.store()
        (self.web_root / IMAGE).write_bytes(b"legacy image")
        self.assertIn("STATUS=0", self.run_installer_reconcile().stdout)
        self.assertFalse(self.link().is_symlink())

    def test_the_installer_corrects_a_link_to_another_copy(self):
        self.store()
        self.link().symlink_to("elsewhere/" + IMAGE)
        self.assertIn("STATUS=0", self.run_installer_reconcile().stdout)
        self.assertEqual(os.readlink(self.link()), f"provision-uploads/{IMAGE}")

    def test_the_installer_reconciles_during_the_web_permission_step(self):
        """Without the call site the helper would never run on an update."""
        self.assertRegex(
            INSTALL_SH.read_text(encoding="utf-8"),
            r'republish_provision_image_links "\$WEB_ROOT"')

    def test_the_docker_entrypoint_still_republishes_every_stored_image(self):
        """Both deployments must reconcile; neither may be the only one."""
        self.assertIn('_publish_provision_link "$(basename "$stored_image")"',
                      DOCKER_ENTRYPOINT)

    # ---------- the UI must surface what it cannot heal ----------

    def test_the_image_list_warns_when_an_image_is_not_served(self):
        self.assertIn("img.served === false", PROVISION_HTML)
        self.assertIn("Not served", PROVISION_HTML)

    def test_use_for_ztp_warns_before_arming_an_unreachable_image(self):
        self.assertIn("ztpImagesUnserved", PROVISION_HTML)


if __name__ == "__main__":
    unittest.main()
