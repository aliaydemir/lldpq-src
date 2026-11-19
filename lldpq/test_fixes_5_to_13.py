#!/usr/bin/env python3
"""Regression tests for fixes #5 through #13 across telemetry, exports, Ansible
editor, Provision SSH user / async deploy, alert strategy, monitor CLI help,
transceiver comment accuracy, and Provision dead code removal.
"""
from __future__ import annotations

import base64
import contextlib
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lldpq"))


class TelemetryAlertRulesTests(unittest.TestCase):
    """#5: Prometheus alert_rules.yaml must match Cumulus OTEL cumulus_nvswitch_* schema."""

    def test_alert_rules_match_cumulus_otel_metrics_and_labels(self):
        rules_path = ROOT / "telemetry" / "config" / "alert_rules.yaml"
        rules_text = rules_path.read_text(encoding="utf-8")
        parsed = yaml.safe_load(rules_text)
        self.assertIsInstance(parsed, dict)
        groups = parsed.get("groups") or []
        self.assertGreaterEqual(len(groups), 2)

        # Must not reference stale non-existent metric names or $labels.device
        for forbidden in (
            "cumulus_interface_",
            "cumulus_bgp_",
            "cumulus_platform_",
            "$labels.device",
        ):
            self.assertNotIn(forbidden, rules_text)

        # Every cumulus_nvswitch_* metric referenced in alert_rules.yaml must be a
        # real metric queried by html/telemetry.html.
        telemetry_html = (ROOT / "html" / "telemetry.html").read_text(encoding="utf-8")
        html_metrics = set(re.findall(r"cumulus_nvswitch_[a-z0-9_]+", telemetry_html))
        rule_metrics = set(re.findall(r"cumulus_nvswitch_[a-z0-9_]+", rules_text))
        self.assertTrue(rule_metrics, "Expected cumulus_nvswitch_* metrics in alert_rules.yaml")
        self.assertTrue(
            rule_metrics.issubset(html_metrics),
            f"Unknown metrics not in telemetry.html: {sorted(rule_metrics - html_metrics)}",
        )
        self.assertIn("$labels.net_host_name", rules_text)
        self.assertIn("$labels.interface", rules_text)


class ExportIndexAiContractTests(unittest.TestCase):
    """#6: /export_json AI availability must match /ai/export_json's contract."""

    def _run_cgi(self, script: Path, env: dict) -> tuple[str, str]:
        result = subprocess.run(
            ["bash", str(script)],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        headers, _, body = result.stdout.partition("\n\n")
        return headers, body

    def test_seeded_empty_ai_analysis_is_unavailable_in_export_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            web = root / "web"
            ai_dir = root / "ai"
            (web / "monitor-results" / "export").mkdir(parents=True)
            ai_dir.mkdir(parents=True)
            helper = root / "lldpq-config"
            helper.write_text(
                f"#!/usr/bin/env bash\n"
                f"printf 'LLDPQ_DIR=%q\\nWEB_ROOT=%q\\n' {str(ROOT / 'lldpq')!r} {str(web)!r}\n",
                encoding="utf-8",
            )
            helper.chmod(0o755)

            # Seeded empty {} object (as created by install.sh / Dockerfile)
            (ai_dir / "analysis.json").write_text("{}\n", encoding="utf-8")

            env = {
                **os.environ,
                "REQUEST_METHOD": "GET",
                "LLDPQ_CONFIG_HELPER": str(helper),
                "AI_STATE_DIR": str(ai_dir),
            }
            _, idx_body = self._run_cgi(ROOT / "html" / "export-api.sh", env)
            idx = json.loads(idx_body)
            ai_entry = next(r for r in idx["reports"] if r["report"] == "ai")
            self.assertFalse(ai_entry["available"])
            self.assertIsNone(ai_entry["updated"])

            ai_headers, _ = self._run_cgi(ROOT / "html" / "ai-export-api.sh", env)
            self.assertIn("Status: 503", ai_headers)

            # Once populated with timestamp + analysis, both endpoints agree
            (ai_dir / "analysis.json").write_text(
                json.dumps({"timestamp": "2026-11-19T12:00:00Z", "analysis": "OK"}),
                encoding="utf-8",
            )
            _, idx_body2 = self._run_cgi(ROOT / "html" / "export-api.sh", env)
            idx2 = json.loads(idx_body2)
            ai_entry2 = next(r for r in idx2["reports"] if r["report"] == "ai")
            self.assertTrue(ai_entry2["available"])
            self.assertIsNotNone(ai_entry2["updated"])

            ai_headers2, _ = self._run_cgi(ROOT / "html" / "ai-export-api.sh", env)
            self.assertIn("Status: 200 OK", ai_headers2)


class AnsibleEditorConcurrencyAndPushTests(unittest.TestCase):
    """#7: Optimistic revision locking on write and unpushed-commit push retry."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.html_dir = self.root / "html"
        self.html_dir.mkdir()
        # Copy ansible-api.sh beside a stub auth-guard.sh so the CGI runs isolated.
        shutil.copy2(ROOT / "html" / "ansible-api.sh", self.html_dir / "ansible-api.sh")
        (self.html_dir / "auth-guard.sh").write_text(
            "#!/usr/bin/env bash\nrequire_admin() { LLDPQ_AUTH_USER=admin; LLDPQ_AUTH_ROLE=admin; }\n",
            encoding="utf-8",
        )
        self.ansible_dir = self.root / "ansible"
        self.ansible_dir.mkdir()
        self.lock_dir = self.root / "locks"
        self.lock_dir.mkdir()

    def _call_cgi(self, query: str, body: bytes = b"", method: str = "GET",
                  extra_env: dict | None = None) -> dict:
        env = {
            **os.environ,
            "REQUEST_METHOD": method,
            "QUERY_STRING": query,
            "CONTENT_LENGTH": str(len(body)) if body else "",
            "ANSIBLE_DIR": str(self.ansible_dir),
            "EDITOR_ROOT": str(self.ansible_dir),
            "LLDPQ_DIR": str(ROOT / "lldpq"),
            "FABRIC_LOCK_DIR": str(self.lock_dir),
            "FABRIC_LOCK_FILE": str(self.lock_dir / "fabric-api.lock"),
        }
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run(
            ["bash", str(self.html_dir / "ansible-api.sh")],
            input=body,
            env=env,
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode("utf-8", errors="replace"))
        stdout = proc.stdout.decode("utf-8", errors="replace")
        _, _, payload = stdout.partition("\n\n")
        return json.loads(payload)

    def test_optimistic_revision_prevents_stale_overwrite_and_create_only_guards_new_files(self):
        target = self.ansible_dir / "leaf1.yaml"
        target.write_text("mtu: 9000\n", encoding="utf-8")

        read1 = self._call_cgi("action=read&file=leaf1.yaml")
        self.assertTrue(read1["success"])
        rev1 = read1["revision"]
        self.assertEqual(rev1, hashlib.sha256(b"mtu: 9000\n").hexdigest())

        # Writer A saves with current revision -> succeeds and returns new revision
        body_a = json.dumps({"content": "mtu: 9216\n", "expected_revision": rev1}).encode()
        res_a = self._call_cgi("action=write&file=leaf1.yaml", body=body_a, method="POST")
        self.assertTrue(res_a["success"], res_a)
        rev2 = res_a["revision"]
        self.assertNotEqual(rev2, rev1)
        self.assertEqual(target.read_text(encoding="utf-8"), "mtu: 9216\n")

        # Writer B tries to save using stale rev1 -> rejected with conflict, file untouched
        body_b = json.dumps({"content": "mtu: 1500\n", "expected_revision": rev1}).encode()
        res_b = self._call_cgi("action=write&file=leaf1.yaml", body=body_b, method="POST")
        self.assertFalse(res_b["success"])
        self.assertTrue(res_b.get("conflict"))
        self.assertEqual(res_b.get("current_revision"), rev2)
        self.assertEqual(target.read_text(encoding="utf-8"), "mtu: 9216\n")

        # create_only rejects overwriting an existing file
        body_create = json.dumps({"content": "new: true\n", "create_only": True}).encode()
        res_create = self._call_cgi("action=write&file=leaf1.yaml", body=body_create, method="POST")
        self.assertFalse(res_create["success"])
        self.assertTrue(res_create.get("conflict"))
        self.assertEqual(target.read_text(encoding="utf-8"), "mtu: 9216\n")

    def test_git_commit_retries_push_for_already_committed_pending_commits(self):
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        state_file = self.root / "git_state.json"
        state_file.write_text(
            json.dumps({"staged_dirty": True, "ahead": 0, "fail_push": True, "push_calls": 0}),
            encoding="utf-8",
        )
        fake_git = fake_bin / "git"
        fake_git.write_text(
            f"""#!{sys.executable}
import json, sys
from pathlib import Path

state_path = Path({str(state_file)!r})
state = json.loads(state_path.read_text())
args = sys.argv[1:]

if args[:2] == ["diff", "--cached"] and "--quiet" in args:
    sys.exit(1 if state["staged_dirty"] else 0)
if args[:1] == ["commit"]:
    state["staged_dirty"] = False
    state["ahead"] += 1
    state_path.write_text(json.dumps(state))
    print("[main abc1234] committed")
    sys.exit(0)
if args[:1] == ["rev-parse"] and "@{{u}}" in args:
    print("origin/main")
    sys.exit(0)
if args[:2] == ["rev-list", "--count"]:
    print(state["ahead"])
    sys.exit(0)
if args[:1] == ["push"]:
    state["push_calls"] += 1
    if state["fail_push"]:
        state_path.write_text(json.dumps(state))
        print("fatal: remote temporarily unavailable", file=sys.stderr)
        sys.exit(1)
    state["ahead"] = 0
    state_path.write_text(json.dumps(state))
    print("To origin\\n   0000000..abc1234  main -> main")
    sys.exit(0)
sys.exit(0)
""",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)
        extra = {"PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"}

        # 1st attempt: commit succeeds, push fails
        first = self._call_cgi(
            "action=git-commit", body=b"message=Update+1", method="POST", extra_env=extra
        )
        self.assertFalse(first["success"], first)
        self.assertEqual(first.get("error"), "Push failed")
        st1 = json.loads(state_file.read_text())
        self.assertEqual(st1["ahead"], 1)
        self.assertEqual(st1["push_calls"], 1)

        # Remote recovers; working tree is clean, but 1 commit is still unpushed.
        st1["fail_push"] = False
        state_file.write_text(json.dumps(st1))

        # 2nd attempt: must detect ahead=1 and push instead of returning Nothing to commit
        second = self._call_cgi(
            "action=git-commit", body=b"message=Retry+push", method="POST", extra_env=extra
        )
        self.assertTrue(second["success"], second)
        self.assertIn("Pushed 1 pending commit", second.get("output", ""))
        st2 = json.loads(state_file.read_text())
        self.assertEqual(st2["ahead"], 0)
        self.assertEqual(st2["push_calls"], 2)

        # 3rd attempt: working tree clean AND ahead=0 -> Nothing to commit
        third = self._call_cgi(
            "action=git-commit", body=b"message=Nothing", method="POST", extra_env=extra
        )
        self.assertTrue(third["success"], third)
        self.assertIn("Nothing to commit", third.get("output", ""))
        st3 = json.loads(state_file.read_text())
        self.assertEqual(st3["push_calls"], 2)

    def test_frontend_editor_tracks_revision_and_handles_conflict(self):
        html = (ROOT / "html" / "fabric-editor.html").read_text(encoding="utf-8")
        self.assertIn("expected_revision", html)
        self.assertIn("create_only", html)
        self.assertIn("result.conflict", html)


class ProvisionUserAndAsyncDeployTests(unittest.TestCase):
    """#8, #9, #13: Custom SSH usernames, async detached deploy jobs, dead-code removal."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.collector = self.root / "collector"
        self.web = self.root / "web"
        self.base = self.collector / "sw-base"
        self.uploads = self.web / "provision-uploads"
        self.generated = self.web / "generated_config_folder"
        for d in (self.base, self.uploads, self.generated):
            d.mkdir(parents=True)

        (self.collector / "devices.yaml").write_text(
            yaml.safe_dump({
                "defaults": {"username": "swops"},
                "devices": {
                    "192.0.2.10": {"hostname": "leaf-custom", "username": "netadmin"},
                    "192.0.2.11": "leaf-default @leaf",
                },
            }),
            encoding="utf-8",
        )
        (self.web / "inventory.json").write_text(
            json.dumps({
                "bindings": [
                    {"hostname": "leaf-custom", "ip": "192.0.2.10",
                     "mac": "aa:bb:cc:dd:ee:10", "dhcp": True},
                    {"hostname": "leaf-default", "ip": "192.0.2.11",
                     "mac": "aa:bb:cc:dd:ee:11", "dhcp": True},
                ]
            }),
            encoding="utf-8",
        )
        (self.base / "tmux.conf").write_text("set -g history-limit 5000\n", encoding="utf-8")
        (self.generated / "leaf-custom.yaml").write_text("set:\n  system:\n    hostname: leaf-custom\n", encoding="utf-8")
        (self.generated / "leaf-default.yaml").write_text("set:\n  system:\n    hostname: leaf-default\n", encoding="utf-8")

        source = (ROOT / "html" / "provision-api.sh").read_text(encoding="utf-8")
        body = source.split("python3 << 'PYTHON_SCRIPT'\n", 1)[1].split(
            "# ======================== ROUTER ========================", 1
        )[0]
        env = {
            "LLDPQ_DIR": str(self.collector),
            "WEB_ROOT": str(self.web),
            "BASE_CONFIG_DIR": str(self.base),
            "PROVISION_UPLOAD_DIR": str(self.uploads),
            "ZTP_SCRIPT_FILE": str(self.web / "cumulus-ztp.sh"),
            "PROVISION_SERVER_IP": "192.0.2.250",
            "DHCP_HOSTS_FILE": str(self.root / "no-dhcpd.hosts"),
            "DHCP_CONF_FILE": str(self.root / "no-dhcpd.conf"),
        }
        patch = mock.patch.dict(os.environ, env)
        patch.start()
        self.addCleanup(patch.stop)
        self.api = {}
        exec(compile(body, "provision-api.sh", "exec"), self.api)
        self.api.update(
            UPGRADE_JOBS_DIR=str(self.root / "upgrade-jobs"),
            DISCOVERY_JOBS_DIR=str(self.root / "provision-jobs"),
        )
        self.api["launch_deploy_worker"] = mock.Mock(return_value=999)
        self.ssh_targets = []

        def fake_run(cmd, *args, **kwargs):
            for tok in cmd:
                if isinstance(tok, str) and "@" in tok:
                    self.ssh_targets.append(tok)
            if "scp" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            script_in = kwargs.get("input", "")
            if "LLDPQ_CONFIG_OK" in script_in:
                return subprocess.CompletedProcess(cmd, 0, "LLDPQ_IDENTITY_OK\nLLDPQ_CONFIG_OK\n", "")
            if "LLDPQ_BASE_OK" in script_in:
                return subprocess.CompletedProcess(cmd, 0, "LLDPQ_IDENTITY_OK\nLLDPQ_BASE_OK\n", "")
            return subprocess.CompletedProcess(cmd, 0, "LLDPQ_IDENTITY_OK\nok\n", "")

        sp = mock.patch("subprocess.run", side_effect=fake_run)
        sp.start()
        self.addCleanup(sp.stop)

    def test_dead_code_action_discovered_removed(self):
        source = (ROOT / "html" / "provision-api.sh").read_text(encoding="utf-8")
        self.assertNotIn("def action_discovered(", source)
        self.assertNotIn("ACTION == 'discovered'", source)
        self.assertNotIn("cumulus@{ip}", source)

    def test_generated_config_deploy_uses_devices_yaml_username_and_defaults(self):
        r1 = self.api["deploy_config_to_device"](
            {"hostname": "leaf-custom", "ip": "192.0.2.10", "config_filename": "leaf-custom.yaml"}
        )
        self.assertTrue(r1["success"], r1)
        r2 = self.api["deploy_config_to_device"](
            {"hostname": "leaf-default", "ip": "192.0.2.11", "config_filename": "leaf-default.yaml"}
        )
        self.assertTrue(r2["success"], r2)
        self.assertIn("netadmin@192.0.2.10", self.ssh_targets)
        self.assertIn("swops@192.0.2.11", self.ssh_targets)
        self.assertFalse(any(t.startswith("cumulus@") for t in self.ssh_targets))

    def test_async_base_deploy_job_runs_worker_and_resumes_idempotently(self):
        devices, files, disable_ztp = self.api["prepare_base_config_deploy"]({
            "devices": [
                {"hostname": "leaf-custom", "ip": "192.0.2.10"},
                {"hostname": "leaf-default", "ip": "192.0.2.11"},
            ],
            "files": ["tmux.conf"],
        })
        self.assertEqual({d["hostname"]: d["username"] for d in devices},
                         {"leaf-custom": "netadmin", "leaf-default": "swops"})

        job = self.api["start_deploy_job"](
            "base_config", devices, files=files, disable_ztp=disable_ztp
        )
        self.api["launch_deploy_worker"].assert_called_once_with(job["id"])

        # Simulate a partial crash where leaf-custom already completed before restart
        job["results"] = [{"ip": "192.0.2.10", "hostname": "leaf-custom", "success": True, "message": "1 files deployed"}]
        job["completed"] = 1
        self.api["save_deploy_job"](job)

        self.api["run_deploy_worker"](job["id"])
        final = self.api["load_deploy_job"](job["id"])
        self.assertTrue(final["complete"])
        self.assertEqual(final["status"], "success")
        self.assertEqual(final["summary"], {"ok": 2, "fail": 0, "total": 2})
        # Only the remaining device (leaf-default -> swops) was contacted on resume
        self.assertTrue(any(t.startswith("swops@192.0.2.11") for t in self.ssh_targets))
        self.assertFalse(any("192.0.2.10" in t for t in self.ssh_targets))

    def test_async_config_deploy_freezes_snapshot_and_hides_b64_from_public_status(self):
        canonical, snapshots, err = self.api["prepare_generated_config_deploy"]({
            "hostname": "leaf-custom", "ip": "192.0.2.10"
        })
        self.assertIsNone(err)
        expected_sha = hashlib.sha256(snapshots["leaf-custom.yaml"]).hexdigest()
        job = self.api["start_deploy_job"](
            "generated_config", canonical, config_snapshots=snapshots
        )
        pub = self.api["public_deploy_job"](job)
        self.assertNotIn("config_snapshots_b64", pub)

        # Mutate the file on disk before the worker runs -> frozen snapshot still wins
        (self.generated / "leaf-custom.yaml").write_text("set:\n  system:\n    hostname: mutated\n", encoding="utf-8")

        self.api["run_deploy_worker"](job["id"])
        final = self.api["load_deploy_job"](job["id"])
        self.assertTrue(final["complete"])
        self.assertEqual(final["status"], "success")
        self.assertNotIn("config_snapshots_b64", final)
        self.assertEqual(final["results"][0]["config_sha256"], expected_sha)
        self.assertIn("netadmin@192.0.2.10", self.ssh_targets)

    def test_provision_html_uses_async_deploy_endpoints(self):
        html = (ROOT / "html" / "provision.html").read_text(encoding="utf-8")
        self.assertIn("'base-deploy-start'", html)
        self.assertIn("'base-deploy-status'", html)
        self.assertIn("'config-deploy-start'", html)
        self.assertIn("'config-deploy-status'", html)


class AlertStrategyFeaturesTests(unittest.TestCase):
    """#10: always_immediate, change_threshold, daily_summary, weekly_report."""

    def setUp(self):
        import check_alerts
        self.check_alerts = check_alerts
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.site = Path(self.tmp.name)
        (self.site / "monitor-results" / "hardware-data").mkdir(parents=True)
        (self.site / "alert-states").mkdir(parents=True)

    def _make_checker(self, config: dict):
        (self.site / "notifications.yaml").write_text(
            yaml.safe_dump(config), encoding="utf-8"
        )
        checker = self.check_alerts.LLDPqAlerts(str(self.site))
        checker.delivered = []

        def fake_send(title, message, severity, device, alert_type=""):
            checker.delivered.append((severity, device, alert_type, title, message))
            return True

        checker.send_notification = fake_send
        return checker

    def test_notifications_yaml_has_no_not_implemented_markers(self):
        text = (ROOT / "lldpq" / "notifications.yaml").read_text(encoding="utf-8")
        self.assertNotIn("NOT IMPLEMENTED YET", text)
        self.assertNotIn("not implemented yet", text)

    def test_always_immediate_fires_critical_cpu_and_recovers_in_summary_mode(self):
        cfg = {
            "notifications": {"enabled": True, "slack": {"enabled": True, "webhook": "https://example.invalid"}},
            "thresholds": {"hardware": {"cpu_temp_critical": 85, "cpu_temp_warning": 75}},
            "alert_strategy": {"mode": "summary", "always_immediate": ["cpu_temp_critical"]},
            "frequency": {"min_interval_minutes": 0, "retry_interval_minutes": 0, "send_recovery": True},
            "alert_types": {"hardware_alerts": True, "network_alerts": True, "system_alerts": True},
        }
        hw = self.site / "monitor-results" / "hardware-data" / "sw1_hardware.txt"

        # Warning (80C) does NOT trigger critical bypass
        hw.write_text("CPU ACPI temp: +80.0°C\n", encoding="utf-8")
        c1 = self._make_checker(cfg)
        c1.check_always_immediate_alerts(["sw1"])
        self.assertEqual(c1.delivered, [])

        # Critical (90C) triggers immediate alert
        hw.write_text("CPU ACPI temp: +90.0°C\n", encoding="utf-8")
        c2 = self._make_checker(cfg)
        c2.check_always_immediate_alerts(["sw1"])
        self.assertEqual(len(c2.delivered), 1)
        self.assertEqual(c2.delivered[0][0], "CRITICAL")
        self.assertEqual(c2.delivered[0][2], "cpu_temp")

        # Recovery (65C) triggers RECOVERED
        hw.write_text("CPU ACPI temp: +65.0°C\n", encoding="utf-8")
        c3 = self._make_checker(cfg)
        c3.check_always_immediate_alerts(["sw1"])
        self.assertEqual(len(c3.delivered), 1)
        self.assertEqual(c3.delivered[0][0], "RECOVERED")

    def test_change_threshold_detects_temperature_and_fan_deltas(self):
        cfg = {
            "notifications": {"enabled": True, "slack": {"enabled": True, "webhook": "https://example.invalid"}},
            "alert_strategy": {
                "mode": "change_only",
                "change_threshold": {
                    "temperature_change": 10,
                    "fan_change": 1000,
                    "device_count_change": 1,
                },
            },
        }
        hw = self.site / "monitor-results" / "hardware-data" / "sw1_hardware.txt"
        hw.write_text("CPU ACPI temp: +55.0°C\nfan1: 5000 RPM\n", encoding="utf-8")

        checker = self._make_checker(cfg)
        m1 = checker._collect_change_metrics(["sw1"], {"successful": 2})
        self.assertEqual(checker._detect_metric_threshold_changes(m1), [])
        checker._write_change_metrics_baseline(m1)

        # Small change (+4C, -200 RPM) -> below threshold
        hw.write_text("CPU ACPI temp: +59.0°C\nfan1: 4800 RPM\n", encoding="utf-8")
        m2 = checker._collect_change_metrics(["sw1"], {"successful": 2})
        self.assertEqual(checker._detect_metric_threshold_changes(m2), [])

        # Large jump (+15C and -1500 RPM and 1 device offline) -> all reported
        hw.write_text("CPU ACPI temp: +70.0°C\nfan1: 3500 RPM\n", encoding="utf-8")
        m3 = checker._collect_change_metrics(["sw1"], {"successful": 1})
        changes = checker._detect_metric_threshold_changes(m3)
        self.assertTrue(any("Online devices" in c for c in changes), changes)
        self.assertTrue(any("CPU temp" in c for c in changes), changes)
        self.assertTrue(any("fan speed" in c for c in changes), changes)

    def test_daily_summary_toggle_and_weekly_report_slot(self):
        class FakeMonday(datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 11, 16, 10, 0, 0)  # Monday

        class FakeTuesday(datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                return cls(2026, 11, 17, 10, 0, 0)  # Tuesday

        # daily_summary=False suppresses scheduled daily slots
        c_off = self._make_checker({
            "notifications": {"enabled": True, "slack": {"enabled": True, "webhook": "https://example.invalid"}},
            "alert_strategy": {"mode": "summary", "summary_times": ["09:00"]},
            "frequency": {"daily_summary": False, "weekly_report": True},
        })
        with mock.patch.object(self.check_alerts.datetime, "datetime", FakeMonday):
            self.assertIsNone(c_off.due_summary_slot())
            self.assertEqual(c_off.due_weekly_slot(), "2026-W47")
            c_off.set_alert_state("network_summary", "last_summary", "sig1")
            self.assertTrue(c_off.should_send_summary_alert("sig1"))
            c_off.set_alert_state("network_summary", "last_weekly_report", "2026-W47")
            self.assertFalse(c_off.should_send_summary_alert("sig1"))

        with mock.patch.object(self.check_alerts.datetime, "datetime", FakeTuesday):
            self.assertIsNone(c_off.due_weekly_slot())


class CliHelpAndHeaderAccuracyTests(unittest.TestCase):
    """#11 and #12: monitor.sh --help lists all scopes; collect-transceiver-fw header accurate."""

    def test_monitor_help_lists_all_supported_only_scopes(self):
        proc = subprocess.run(
            ["bash", str(ROOT / "lldpq" / "monitor.sh"), "--help"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for scope in (
            "bgp", "evpn-mh", "duplicate", "flap", "optical", "ber",
            "pfc-ecn", "hardware", "logs", "config-drift", "routes", "fabric-check", "all",
        ):
            self.assertIn(scope, proc.stdout)

    def test_collect_transceiver_fw_header_reflects_lldpq_trigger_architecture(self):
        head = "\n".join(
            (ROOT / "lldpq" / "collect-transceiver-fw.sh").read_text(encoding="utf-8").splitlines()[:8]
        )
        self.assertNotIn("not triggered from web UI", head)
        self.assertIn("lldpq-trigger", head)


if __name__ == "__main__":
    unittest.main()
