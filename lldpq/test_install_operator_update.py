"""Exercise the native installer's cross-account update checks without sudo."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
INSTALL = (ROOT / "install.sh").read_text()


def installer_helper(body, *args):
    script = """
        LLDPQ_INSTALL_LIB_ONLY=true source ./install.sh
        sudo() { echo "unexpected sudo invocation: $*" >&2; return 97; }
        # /home on macOS is a symlink. Model the Linux paths used by these fixtures.
        if ! realpath -m -- . >/dev/null 2>&1; then
            canonical_path() { printf '%s\n' "$1"; }
        fi
    """ + body
    return subprocess.run(
        ["bash", "-c", script, "test", *args],
        cwd=ROOT, text=True, capture_output=True, timeout=10,
    )


@unittest.skipUnless(sys.platform == "linux" and shutil.which("flock"),
                     "native lock handoff uses Linux procfs and flock")
class AdminCollectionLockTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.lock = Path(folder.name) / "collector.lock"

    def run_lock(self, body):
        return installer_helper("""
            ADMIN_UPDATE=true
            LLDPQ_USER=$(id -un)
            LLDPQ_MONITOR_LOCK_FILE=$1
            LLDPQ_UPDATE_LOCK_TIMEOUT=1
            sudo() {
                [[ $1 == -H && $2 == -u && $3 == "$LLDPQ_USER" && $4 == python3 ]] || return 97
                printf '%s' "$3" > "$LLDPQ_MONITOR_LOCK_FILE.creator"
                shift 3
                "$@"
            }
        """ + body, str(self.lock))

    def test_existing_inode_is_locked_without_truncating(self):
        self.lock.write_text("collector")
        before = self.lock.stat()
        result = self.run_lock("""
            acquire_update_process_lock
            if flock -n "$1" true; then exit 3; fi
            release_update_process_lock
            flock -n "$1" true
        """)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.lock.read_text(), "collector")
        self.assertEqual(self.lock.stat().st_ino, before.st_ino)
        self.assertFalse(self.lock.with_suffix(".lock.creator").exists())

    def test_missing_lock_is_created_as_the_service_account(self):
        result = self.run_lock("acquire_update_process_lock && release_update_process_lock")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.lock.with_suffix(".lock.creator").is_file())
        self.assertEqual(self.lock.stat().st_uid, os.getuid())

    def test_symlink_hard_link_and_fifo_are_rejected(self):
        other = self.lock.with_name("other")
        other.write_text("preserve this file")
        for kind in ("symlink", "hard link", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    self.lock.symlink_to(other)
                elif kind == "hard link":
                    os.link(other, self.lock)
                else:
                    os.mkfifo(self.lock)
                result = self.run_lock("""
                    if acquire_update_process_lock; then exit 3; fi
                    [[ -z "$UPDATE_PROCESS_LOCK_FD" ]]
                """)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(other.read_text(), "preserve this file")
                self.lock.unlink()

    def test_replacement_while_waiting_cancels_update(self):
        self.lock.touch()
        result = self.run_lock("""
            flock() {
                command flock "$@" || return 1
                if [[ $1 == -w ]]; then
                    mv "$LLDPQ_MONITOR_LOCK_FILE" "$LLDPQ_MONITOR_LOCK_FILE.old"
                    touch "$LLDPQ_MONITOR_LOCK_FILE"
                fi
            }
            if acquire_update_process_lock; then exit 3; fi
            [[ -z "$UPDATE_PROCESS_LOCK_FD" ]]
            command flock -n "$1.old" true
        """)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("changed while waiting", result.stderr)


class AdminRecoveryTests(unittest.TestCase):
    def setUp(self):
        # Exercise the stage selection and the boot helper on the same simulated
        # two-filesystem layout. No system directories or real owners are needed.
        self.runtime = Path("/home/service/lldpq")
        self.preserve = Path("/home/.lldpq-data-preserve.test")
        self.rollback = Path("/home/.lldpq-update-rollback.test")
        self.payload = {
            "install_dir": str(self.runtime),
            "web_root": "/var/www/html",
            "preserve_dir": str(self.preserve),
            "rollback_dir": str(self.rollback),
            "admin_staging": True,
        }
        self.files = {
            path: SimpleNamespace(st_uid=uid, st_dev=device, st_mode=0o40700)
            for path, uid, device in [(Path("/"), 0, 1), (Path("/home"), 0, 2),
                                      (self.runtime.parent, 1001, 2), (self.runtime, 1001, 2),
                                      (self.preserve, 0, 2), (self.rollback, 0, 2)]
        }
        for method in ("stat", "lstat"):
            mocked = patch.object(Path, method, autospec=True, side_effect=self.files.__getitem__)
            mocked.start()
            self.addCleanup(mocked.stop)
        helper = INSTALL.split('cat > "$helper_tmp" <<\'PYTHON\'\n', 1)[1]
        program = helper.split("\nPYTHON\n", 1)[0]
        recovery = {"__name__": "test_update_recovery"}
        exec(compile(program, "lldpq-update-recovery.py", "exec"), recovery)
        self.validate = recovery["validate_paths"]

    def test_stage_selection_and_boot_recovery_agree(self):
        helper = INSTALL.split("admin_update_stage_parent() {", 1)[1]
        stage = helper.split("<<'PYTHON'\n", 1)[1].split("\nPYTHON\n", 1)[0]
        with patch.object(sys, "argv", ["stage", str(self.runtime)]), \
             patch.object(Path, "is_mount", return_value=False), \
             patch("sys.stdout", new_callable=StringIO) as output:
            exec(compile(stage, "admin_update_stage_parent", "exec"), {})
        self.assertEqual(output.getvalue().strip(), str(self.rollback.parent))
        self.assertEqual(self.validate(self.payload)[2:], (self.preserve, self.rollback))

    def test_recovery_rejects_writable_stage_even_before_runtime_is_moved(self):
        self.files[Path("/home")].st_mode |= 0o020
        self.payload["rollback_dir"] = None
        with self.assertRaisesRegex(RuntimeError, "unsafe admin snapshot"):
            self.validate(self.payload)

    def test_legacy_recovery_still_requires_sibling_rollback(self):
        del self.payload["admin_staging"]
        with self.assertRaisesRegex(RuntimeError, "rollback directory"):
            self.validate(self.payload)


class OperatorUpdateTests(unittest.TestCase):
    def test_admin_update_cli_rejects_mixed_modes_and_config_overrides(self):
        command = ["bash", "./install.sh", "--admin-update"]
        for incompatible in ("--enable-telemetry", "--disable-telemetry", "--replace-dhcp-config"):
            with self.subTest(incompatible=incompatible):
                result = subprocess.run(command + [incompatible], cwd=ROOT,
                                        text=True, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("cannot be combined", result.stderr)
        result = subprocess.run(
            command, cwd=ROOT, env=dict(os.environ, LLDPQ_CONFIG_FILE="/tmp/test-lldpq.conf"),
            text=True, capture_output=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("/etc/lldpq.conf", result.stderr)

    def test_full_backup_collects_the_service_users_keys(self):
        backup_keys = INSTALL.split("        # SSH keys\n", 1)[1].split("        # The README", 1)[0]
        with tempfile.TemporaryDirectory() as folder:
            service_home = Path(folder) / "service"
            key_dir = service_home / ".ssh"
            key_dir.mkdir(parents=True)
            (key_dir / "id_test").touch()
            backup = Path(folder) / "backup"
            result = installer_helper(
                """
                LLDPQ_USER_HOME="$1"
                BACKUP_DIR="$2"
                _backup_copy() { printf '%s\\n' "$1" >> "$BACKUP_DIR/files"; }
                """ + backup_keys,
                str(service_home), str(backup),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((backup / "files").read_text().splitlines(), [str(key_dir / "id_test")])

    def test_admin_update_keeps_the_existing_source_and_service_account_in_config(self):
        # Run the actual config rendering statements against a temporary file.
        block = INSTALL.split('echo "# LLDPq Configuration"', 1)[1]
        render_identity = 'echo "# LLDPq Configuration"' + block.split("_LLDPQ_HOSTNAME_TO_WRITE=", 1)[0]
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "lldpq.conf"
            result = installer_helper(
                """
                ADMIN_UPDATE=true
                INSTALL_MODE=update
                LLDPQ_INSTALL_DIR=/home/lldpq-test-service/lldpq
                LLDPQ_USER=lldpq-test-service
                LLDPQ_SRC=/home/lldpq-test-service/lldpq-src
                LLDPQ_CONFIG_LOADED_KEYS[LLDPQ_SRC]=1
                LLDPQ_SRC_DIR=/home/lldpq-test-operator/lldpq-src
                _lldpq_conf_render="$1"
                """ + render_identity, str(config),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            assignments = config.read_text().splitlines()
            self.assertIn("LLDPQ_DIR=/home/lldpq-test-service/lldpq", assignments)
            self.assertIn("LLDPQ_USER=lldpq-test-service", assignments)
            self.assertIn("LLDPQ_SRC=/home/lldpq-test-service/lldpq-src", assignments)

    def test_admin_update_keeps_temporarily_unavailable_ansible_paths(self):
        block = INSTALL.split('step "Configuring Ansible directory..."', 1)[1]
        configure = block.split("# COMMON: Write /etc/lldpq.conf", 1)[0]
        with tempfile.TemporaryDirectory(dir=ROOT) as folder:
            expected = str(Path(folder) / "service-project")
            result = installer_helper(
                """
                ADMIN_UPDATE=true
                INSTALL_MODE=update
                _SAVE_ANSIBLE_DIR="$1"
                _SAVE_EDITOR_ROOT="$1/editor"
                LLDPQ_USER_HOME="$1"
                """ + configure + '\nprintf "%s\\n" "$ANSIBLE_DIR" "$EDITOR_ROOT"',
                expected,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines()[-2:], [expected, expected + "/editor"])

    def test_verified_service_home_can_be_used_for_the_existing_install(self):
        result = installer_helper(
            'guard_recursive_target "LLDPq install" "$1" false "$2"',
            "/home/lldpq-test-service/lldpq", "/home/lldpq-test-service",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "/home/lldpq-test-service/lldpq")

    def test_verified_service_home_does_not_authorize_other_users_or_system_trees(self):
        for target in (
            "/home/lldpq-test-service-2/lldpq", "/root/lldpq", "/etc/lldpq",
            "/home/lldpq-test-service",
        ):
            with self.subTest(target=target):
                result = installer_helper(
                    'guard_recursive_target "LLDPq install" "$1" false "$2"',
                    target, "/home/lldpq-test-service",
                )
                self.assertNotEqual(result.returncode, 0)

    def test_fresh_cross_home_targets_are_rejected(self):
        for label, path in (
            ("LLDPq install", "/home/lldpq-test-service/lldpq"),
            ("web root", "/home/lldpq-test-service/www"),
            ("Ansible project", "/home/lldpq-test-service/ansible"),
            ("editor root", "/home/lldpq-test-service/editor"),
        ):
            with self.subTest(target=label):
                result = installer_helper(
                    'guard_recursive_target "$1" "$2" false', label, path
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("another user's home", result.stderr)


class AdminUpdatePreflightTests(unittest.TestCase):
    """Run argument parsing, config loading, both validators and mode selection together."""

    def setUp(self):
        scratch = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(scratch.cleanup)
        root = Path(scratch.name).resolve()
        self.checkout = root / "operator-checkout"
        self.service_home = root / "service-home"
        self.runtime = self.service_home / "lldpq"
        self.web = self.service_home / "www"
        self.config = root / "lldpq.conf"
        self.unit = root / "lldpq-recovery.service"
        self.config.write_text(f"LLDPQ_USER=service\nLLDPQ_DIR={self.runtime}\nWEB_ROOT={self.web}\n")
        for path in (self.runtime / "monitor.sh", self.runtime / "devices.yaml", self.web / "setup.html"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        for folder in ("bin", "etc", "html", "lldpq", "telemetry"):
            (self.checkout / folder).mkdir(parents=True)
        for name in ("VERSION", "README.md", "uninstall.sh", "lldpq/monitor.sh", "html/setup.html"):
            (self.checkout / name).touch()
        shutil.copy2(ROOT / "bin/lldpq-config", self.checkout / "bin/lldpq-config")
        rendered = installer_helper(
            'render_lldpq_recovery_service "$1" service "$2" "$3"',
            str(self.unit), str(self.runtime), str(self.web),
        )
        self.assertEqual(rendered.returncode, 0, rendered.stderr)

        # Stop before package/service/file installation. Only system paths, privileges and
        # OS account metadata are simulated. Use the real entrypoint and checks otherwise.
        preflight = INSTALL.split("\n# Banner\n", 1)[0]
        for system, fixture in (
            ("/etc/lldpq.conf", self.config),
            ("/etc/systemd/system/lldpq-recovery.service", self.unit),
            ("/usr/local/libexec/lldpq-uninstall-web.py", root / "unused-gateway"),
            ("/run/lldpq-uninstall.active", root / "unused-marker"),
        ):
            preflight = preflight.replace(system, str(fixture))
        preflight = preflight.replace("EUID", "TEST_EUID")
        shims = """
            TEST_EUID=0
            sudo() { echo "unexpected sudo call: $*" >&2; exit 97; }
            getent() { printf 'service:x:1234:1234::%s:/bin/bash\\n' "$TEST_SERVICE_HOME"; }
            id() { if [[ "$*" == '-u service' ]]; then echo 1234; else command id "$@"; fi; }
            stat() {
                case "$2" in
                    %u) echo 1234 ;;
                    %u:%a) echo "${TEST_AUTHORITY_METADATA:-0:755}" ;;
                    *) return 96 ;;
                esac
            }
            realpath() { python3 -c 'import os,sys;print(os.path.realpath(sys.argv[-1]))' "$@"; }
        """
        preflight = preflight.replace("# Step counter for progress display", shims + "\n# Step counter for progress display")
        (self.checkout / "install.sh").write_text(
            preflight + '\nprintf "%s|%s|%s|%s\\n" "$INSTALL_MODE" "$LLDPQ_USER" "$LLDPQ_INSTALL_DIR" "$WEB_ROOT"\n'
        )

    def preflight(self, **extra):
        env = dict(PATH=os.environ["PATH"], SUDO_UID=str(os.getuid()),
                   SUDO_USER="operator", TEST_SERVICE_HOME=str(self.service_home), **extra)
        return subprocess.run(
            ["bash", "./install.sh", "--admin-update", "--backup"],
            cwd=self.checkout, env=env, text=True, input="y\n", capture_output=True, timeout=15,
        )

    def test_installed_account_and_paths_are_selected_even_if_input_requests_a_clean_install(self):
        result = self.preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines()[-1], f"update|service|{self.runtime}|{self.web}")

    def test_config_and_installed_unit_must_agree(self):
        self.unit.write_text(self.unit.read_text().replace('--user "service"', '--user "other"'))
        result = self.preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not confirm", result.stderr)

    def test_group_writable_install_authority_is_rejected(self):
        result = self.preflight(TEST_AUTHORITY_METADATA="0:664")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root-owned", result.stderr)

    def test_missing_installation_is_not_installed_as_fresh(self):
        self.config.unlink()
        result = self.preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing native installation", result.stderr)

    def test_group_writable_release_payload_is_rejected(self):
        (self.checkout / "lldpq/monitor.sh").chmod(0o664)
        result = self.preflight()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release checkout", result.stderr)
        self.assertIn("mode 0664", result.stderr)
