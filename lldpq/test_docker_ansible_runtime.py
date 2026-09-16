#!/usr/bin/env python3
"""Contracts for project-owned Ansible dependencies in the Docker image."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
ANSIBLE_API = (ROOT / "html" / "ansible-api.sh").read_text(encoding="utf-8")
DOCKER_DOC = (ROOT / "DOCKER.md").read_text(encoding="utf-8")


class DockerAnsibleControllerTests(unittest.TestCase):
    def test_controller_and_netaddr_are_pinned(self):
        self.assertEqual(DOCKERFILE.count("ansible-core==2.17.14"), 1)
        self.assertEqual(DOCKERFILE.count("netaddr==1.3.0"), 1)

    def test_ubuntu_legacy_ansible_packages_are_not_installed(self):
        legacy_package_line = re.search(
            r"(?m)^[ \t]*ansible(?:[ \t]+ansible-lint)?[ \t]*\\$",
            DOCKERFILE,
        )
        self.assertIsNone(
            legacy_package_line,
            "Dockerfile still installs the Ubuntu legacy Ansible packages",
        )

    def test_core_build_has_no_galaxy_network_dependency(self):
        self.assertNotIn("ansible-galaxy collection install", DOCKERFILE)
        self.assertNotIn("LLDPQ_INSTALL_ANSIBLE_COLLECTIONS", DOCKERFILE)

    def test_obsolete_hardcoded_collection_helper_is_gone(self):
        self.assertFalse(
            (ROOT / "docker" / "install-ansible-collections.sh").exists()
        )


class ProjectOwnedCollectionTests(unittest.TestCase):
    def test_ansible_api_searches_the_persistent_project_collection_path(self):
        self.assertIn(
            'export ANSIBLE_COLLECTIONS_PATH="$_ansible_collection_root/collections:',
            ANSIBLE_API,
        )
        self.assertIn(
            '_ansible_collection_root="${ANSIBLE_DIR:-$EDITOR_ROOT}"',
            ANSIBLE_API,
        )

    def test_project_path_precedes_ephemeral_and_system_paths(self):
        assignment = next(
            line.strip()
            for line in ANSIBLE_API.splitlines()
            if line.strip().startswith("export ANSIBLE_COLLECTIONS_PATH=")
        )
        project = assignment.index("$_ansible_collection_root/collections")
        ephemeral = assignment.index("$ANSIBLE_HOME/collections")
        system = assignment.index("/usr/share/ansible/collections")
        self.assertLess(project, ephemeral)
        self.assertLess(ephemeral, system)

    def test_documentation_uses_project_requirements_and_persistent_target(self):
        for expected in (
            "ansible-core 2.17.14",
            "netaddr 1.3.0",
            "ansible-galaxy collection install -r requirements.yml -p collections",
            "Ansible searches `$ANSIBLE_DIR/collections`",
        ):
            self.assertIn(expected, DOCKER_DOC)

    def test_documentation_does_not_advertise_the_legacy_collection_set(self):
        self.assertNotIn("LLDPQ_INSTALL_ANSIBLE_COLLECTIONS", DOCKER_DOC)


if __name__ == "__main__":
    unittest.main()
