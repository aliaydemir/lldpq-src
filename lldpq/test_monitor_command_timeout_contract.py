#!/usr/bin/env python3
"""Static/runtime contract for bounded remote monitor commands."""

import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import collection_bundle
import process_optical_data as optical


MONITOR = SCRIPT_DIR / "monitor.sh"
ROOT = MONITOR.parent.parent


class MonitorCommandTimeoutContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = MONITOR.read_text(encoding="utf-8")

    def _interpolate_remote(self, root: Path, scope: str):
        start = self.source.index("    timeout 300 ssh $SSH_OPTS")
        end = self.source.index("\n    local ssh_status=$?", start)
        command = textwrap.dedent(self.source[start:end])
        capture = root / "remote.sh"
        raw_file = root / "raw.txt"
        timeout_stub = root / "timeout"
        ssh_stub = root / "ssh"
        timeout_stub.write_text(
            "#!/bin/sh\n[ \"$1\" = 300 ] || exit 91\nshift\nexec \"$@\"\n",
            encoding="utf-8",
        )
        ssh_stub.write_text(
            "#!/bin/sh\nfor value do remote=$value; done\n"
            "printf '%s\\n' \"$remote\" > \"$LLDPQ_REMOTE_CAPTURE\"\n",
            encoding="utf-8",
        )
        timeout_stub.chmod(0o755)
        ssh_stub.chmod(0o755)
        assignments = "\n".join(
            (
                'SSH_OPTS=""',
                'user="tester"',
                'device="switch.example"',
                'hostname="leaf1"',
                'SKIP_OPTICAL="false"',
                'SKIP_L1="false"',
                'PFC_ECN_COLLECTION_BUDGET_SECONDS="60"',
                'PFC_ECN_PORT_TIMEOUT_SECONDS="5"',
                'PFC_ECN_MAX_PARALLEL="4"',
                'OPTICAL_COLLECTION_BUDGET_SECONDS="120"',
                'OPTICAL_PORT_TIMEOUT_SECONDS="10"',
                'MONITOR_COMMAND_TIMEOUT_SECONDS="20"',
                'MONITOR_TIMING="false"',
                f'MONITOR_SCOPE="{scope}"',
                f'raw_file="{raw_file}"',
            )
        )
        env = dict(os.environ)
        env["PATH"] = str(root) + os.pathsep + env.get("PATH", "")
        env["LLDPQ_REMOTE_CAPTURE"] = str(capture)
        interpolated = subprocess.run(
            ["/bin/bash", "-c", assignments + "\n" + command],
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(interpolated.returncode, 0, interpolated.stderr)
        return capture.read_text(encoding="utf-8"), timeout_stub, env

    def test_timeout_is_validated_injected_and_fails_closed_when_unavailable(self):
        self.assertIn(
            'MONITOR_COMMAND_TIMEOUT_SECONDS="${MONITOR_COMMAND_TIMEOUT_SECONDS:-20}"',
            self.source,
        )
        self.assertIn(
            'MONITOR_COMMAND_TIMEOUT_SECONDS="\'"$MONITOR_COMMAND_TIMEOUT_SECONDS"\'"',
            self.source,
        )
        match = re.search(
            r"(?ms)^        (_lldpq_run_bounded\(\) \{.*?^        \})$",
            self.source,
        )
        self.assertIsNotNone(match)
        helper = textwrap.dedent(match.group(1))
        with tempfile.TemporaryDirectory() as empty_path:
            completed = subprocess.run(
                [
                    "/bin/sh",
                    "-c",
                    helper
                    + "\nMONITOR_COMMAND_TIMEOUT_SECONDS=1\n"
                    + "_lldpq_run_bounded /bin/true\n"
                    + "test $? -eq 125\n",
                ],
                env={"PATH": empty_path},
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        completed = subprocess.run(
            [
                "/bin/sh",
                "-c",
                helper
                + "\nMONITOR_COMMAND_TIMEOUT_SECONDS=1\n"
                + "_lldpq_run_bounded /bin/sh -c 'exit 7'\n"
                + "test $? -eq 7\n",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_interpolated_remote_collector_is_valid_posix_shell(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            remote, timeout_stub, env = self._interpolate_remote(root, "all")
            parsed = subprocess.run(
                ["/bin/sh", "-n"],
                input=remote,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(parsed.returncode, 0, parsed.stderr)

            # Simulate every bounded source timing out.  The remote shell must
            # still finish a structurally complete stream and express failures
            # through existing category-local status markers.
            timeout_stub.write_text("#!/bin/sh\nexit 124\n", encoding="utf-8")
            sensors_stub = root / "sensors"
            sensors_stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            sensors_stub.chmod(0o755)
            timed_out = subprocess.run(
                ["/bin/sh"],
                input=remote,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(timed_out.returncode, 0, timed_out.stderr)
            for marker in (
                "__LLDPQ_COLLECTION_ERROR__:BGP_SUMMARY",
                "__LLDPQ_COLLECTION_ERROR__:EVPN_VNI",
                "__LLDPQ_COLLECTION_ERROR__:EVPN_ROUTES",
                "__LLDPQ_COLLECTION_ERROR__:FDB",
                "__LLDPQ_COLLECTION_ERROR__:NEIGH",
                "__LLDPQ_COLLECTION_ERROR__:LINK_INVENTORY",
                "__LLDPQ_HARDWARE_SOURCE_STATUS__:SENSORS:ERROR",
                "===LOG_DATA_END===",
            ):
                with self.subTest(marker=marker):
                    self.assertIn(marker, timed_out.stdout)

            raw_bundle = root / "timed-out.raw"
            raw_bundle.write_text(timed_out.stdout, encoding="utf-8")
            destinations = {
                section: root / f"{section.lower()}.txt"
                for section in collection_bundle.SECTIONS
            }
            collection_bundle.split_collection_bundle(raw_bundle, destinations)
            self.assertIn(
                "__LLDPQ_COLLECTION_ERROR__:BGP_SUMMARY",
                destinations["BGP_DATA"].read_text(encoding="utf-8"),
            )

    def test_timeoutless_remote_never_runs_ethtool_and_publishes_partial_optical(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            remote, timeout_stub, env = self._interpolate_remote(root, "optical")
            timeout_stub.unlink()

            net_root = root / "sys-class-net"
            port_root = net_root / "swp1"
            port_root.mkdir(parents=True)
            (port_root / "operstate").write_text("up\n", encoding="utf-8")
            remote = remote.replace(
                "_lldpq_net_class_root=/sys/class/net",
                f'_lldpq_net_class_root="{net_root}"',
            )

            sudo_calls = root / "sudo.calls"
            sudo_stub = root / "sudo"
            sudo_stub.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$LLDPQ_SUDO_CALLS\"\n"
                "exit 99\n",
                encoding="utf-8",
            )
            sudo_stub.chmod(0o755)
            # macOS sort lacks GNU -V; this fixture only adapts that platform
            # difference and leaves the captured collector logic unchanged.
            sort_stub = root / "sort"
            sort_stub.write_text(
                "#!/bin/sh\n[ \"$1\" = -V ] && shift\nexec /usr/bin/sort \"$@\"\n",
                encoding="utf-8",
            )
            sort_stub.chmod(0o755)
            env["PATH"] = str(root) + os.pathsep + "/usr/bin:/bin:/usr/sbin:/sbin"
            env["LLDPQ_SUDO_CALLS"] = str(sudo_calls)

            collected = subprocess.run(
                ["/bin/sh"],
                input=remote,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(collected.returncode, 0, collected.stderr)
            marker = "__LLDPQ_COLLECTION_ERROR__:OPTICAL_TOOL_UNAVAILABLE:swp1"
            self.assertIn(marker, collected.stdout)
            self.assertIn("No transceiver data", collected.stdout)
            self.assertFalse(sudo_calls.exists(), "timeoutless optical invoked sudo/ethtool")

            raw_bundle = root / "timeoutless-optical.raw"
            raw_bundle.write_text(collected.stdout, encoding="utf-8")
            destinations = {
                section: root / f"timeoutless-{section.lower()}.txt"
                for section in collection_bundle.SECTIONS
            }
            collection_bundle.split_collection_bundle(raw_bundle, destinations)
            optical_body = destinations["OPTICAL_DATA"].read_text(encoding="utf-8")
            self.assertIn(marker, optical_body)

            result_dir = root / "monitor-results"
            data_dir = result_dir / "optical-data"
            data_dir.mkdir(parents=True)
            (data_dir / "leaf1_optical.txt").write_text(
                optical_body, encoding="utf-8"
            )
            snapshot = ({"leaf1": "OK"}, 1.0, True)
            with (
                mock.patch.object(optical, "read_asset_snapshot", return_value=snapshot),
                mock.patch.object(optical, "asset_snapshot_is_valid", return_value=True),
                mock.patch.object(optical, "is_current_collection", return_value=True),
            ):
                self.assertTrue(optical.process_optical_data_files(str(data_dir)))
            report = (result_dir / "optical-analysis.html").read_text(encoding="utf-8")
            self.assertIn('data-coverage-status="partial"', report)
            self.assertIn(
                "Bounded optical diagnostics are unavailable for swp1", report
            )

    def test_shared_and_category_commands_use_bounded_runner(self):
        required = (
            "_lldpq_run_bounded ip link show",
            "_lldpq_run_bounded ip addr show",
            "_lldpq_run_bounded ip neighbour show",
            "_lldpq_run_bounded sudo /usr/sbin/bridge vlan",
            "_lldpq_run_bounded sudo /usr/sbin/bridge fdb show",
            '_lldpq_run_bounded sudo vtysh -c "show bgp vrf all sum"',
            '_lldpq_run_bounded sudo vtysh -c "show evpn vni"',
            '_lldpq_run_bounded sudo vtysh -c "show bgp l2vpn evpn"',
            "_dup_run ARP_DUPLICATES _lldpq_run_bounded sudo vtysh",
            "_dup_filter MAC_MOBILITY",
            "_lldpq_run_bounded sudo l1-show all -p",
            "_hardware_output=$(_lldpq_run_bounded sensors",
            "_source_output=$(_lldpq_run_bounded sudo journalctl",
            "_source_output=$(_lldpq_run_bounded sudo dmesg",
        )
        for snippet in required:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, self.source)

        self.assertNotRegex(self.source, r"\$\(sudo journalctl\b")
        self.assertNotRegex(self.source, r"\$\(sudo dmesg\b")
        self.assertNotRegex(self.source, r"\$\(sensors\b")
        self.assertNotRegex(self.source, r"(?m)^\s+sudo vtysh\b")

    def test_nonzero_statuses_remain_section_local_and_own_budgets_survive(self):
        for marker in (
            "__LLDPQ_COLLECTION_ERROR__:BGP_SUMMARY",
            "__LLDPQ_COLLECTION_ERROR__:EVPN_VNI",
            "__LLDPQ_COLLECTION_ERROR__:EVPN_ROUTES",
            "__LLDPQ_COLLECTION_ERROR__:FDB",
            "__LLDPQ_COLLECTION_ERROR__:NEIGH",
            "__LLDPQ_COLLECTION_ERROR__:LINK_INVENTORY",
            "__LLDPQ_HARDWARE_SOURCE_STATUS__:SENSORS:ERROR",
            "__LLDPQ_LOG_SOURCE_STATUS__:%s:%s",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source)

        # Optical and PFC retain their per-port/deadline controls; the generic
        # command timeout is only for otherwise-unbounded category sources.
        self.assertIn('timeout -k 1s "${_optical_limit}s"', self.source)
        self.assertIn('timeout -k 1s "${_pfc_worker_limit}s"', self.source)
        self.assertIn("OPTICAL_COLLECTION_BUDGET_SECONDS", self.source)
        self.assertIn("PFC_ECN_COLLECTION_BUDGET_SECONDS", self.source)

    def test_timeout_tuning_survives_install_docker_and_backup_paths(self):
        expected = "MONITOR_COMMAND_TIMEOUT_SECONDS"
        for relative in (
            "bin/lldpq-config",
            "docker/Dockerfile",
            "install.sh",
            "html/setup-api.sh",
            "lldpq/backup_import.py",
            "README.md",
        ):
            with self.subTest(relative=relative):
                content = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn(expected, content)


if __name__ == "__main__":
    unittest.main()
