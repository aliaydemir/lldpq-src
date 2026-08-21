#!/usr/bin/env python3
"""Tests for log severity classification and age reporting.

Two defects made the Logs page misreport real incidents: the syslog priority
was matched anywhere in the message text (so "local-priority: 1" read as
Critical, and a kernel panic carrying "priority = 7" read as Info), and events
were demoted by age, which moved genuine failures out of the Critical count.
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import process_log_data


def analyzer(data_dir="monitor-results"):
    return process_log_data.LogAnalyzer(data_dir)


class SyslogPriorityFieldTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = analyzer()

    def test_message_text_is_not_read_as_a_priority_field(self):
        for line in (
            "frr[1]: local-priority: 1 route installed ok",
            "mstpd: port swp5 priority=0 role designated",
            "qos: switch-priority: 2 mapped to traffic-class 2",
            "nvued: set priority = 1 on interface swp3",
        ):
            with self.subTest(line=line):
                self.assertEqual(
                    self.analyzer.categorize_log_line(line),
                    "info",
                    "a priority mentioned in message text is not a severity",
                )

    def test_a_real_critical_is_not_masked_by_the_word_priority(self):
        line = "qos: traffic-class priority = 7 ... kernel panic imminent"
        self.assertEqual(self.analyzer.categorize_log_line(line), "critical")

    def test_journald_priority_field_is_authoritative(self):
        expected = {
            "0": "critical", "1": "critical", "2": "critical",
            "3": "error", "4": "warning", "5": "info", "6": "info",
            "7": "info",
        }
        for value, severity in expected.items():
            with self.subTest(priority=value):
                line = f"PRIORITY={value} switchd reported something"
                self.assertEqual(
                    self.analyzer.categorize_log_line(line), severity
                )

    def test_syslog_pri_prefix_is_decoded(self):
        # <11> is facility 1, severity 3 (error).
        self.assertEqual(
            self.analyzer.categorize_log_line("<11>frr session dropped"),
            "error",
        )
        # <14> is facility 1, severity 6 (info).
        self.assertEqual(
            self.analyzer.categorize_log_line("<14>frr session established"),
            "info",
        )

    def test_out_of_range_pri_prefix_is_ignored(self):
        self.assertEqual(
            self.analyzer.categorize_log_line("<999>some vendor prefix here"),
            "info",
        )

    def test_known_critical_patterns_still_classify(self):
        line = "kernel: Out of memory: Killed process 900 (switchd)"
        self.assertEqual(self.analyzer.categorize_log_line(line), "critical")


class SectionFloorTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = analyzer()

    def test_priority_filtered_sections_are_at_least_error(self):
        line = "nvued: configuration commit applied"
        for section in ("SYSTEM_CRITICAL_LOGS", "JOURNALCTL_PRIORITY_LOGS"):
            with self.subTest(section=section):
                self.assertEqual(
                    self.analyzer.categorize_log_line(line, section), "error"
                )

    def test_other_sections_keep_the_pattern_verdict(self):
        line = "nvued: configuration commit applied"
        self.assertEqual(
            self.analyzer.categorize_log_line(line, "FRR_LOGS"), "info"
        )

    def test_floor_never_lowers_a_higher_severity(self):
        line = "kernel: Out of memory: Killed process 900 (switchd)"
        self.assertEqual(
            self.analyzer.categorize_log_line(line, "SYSTEM_CRITICAL_LOGS"),
            "critical",
        )


class AgeBucketTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = analyzer()

    def _ago(self, minutes):
        return datetime.now(timezone.utc) - timedelta(minutes=minutes)

    def test_buckets_follow_the_documented_boundaries(self):
        self.assertEqual(self.analyzer.age_bucket(self._ago(5)), "recent")
        self.assertEqual(self.analyzer.age_bucket(self._ago(60)), "aging")
        self.assertEqual(self.analyzer.age_bucket(self._ago(300)), "historical")

    def test_missing_or_naive_timestamps_are_unknown_not_assumed(self):
        self.assertEqual(self.analyzer.age_bucket(None), "unknown")
        self.assertEqual(
            self.analyzer.age_bucket(datetime(2026, 1, 1, 12, 0, 0)), "unknown"
        )

    def test_future_timestamps_do_not_produce_a_stale_bucket(self):
        future = datetime.now(timezone.utc) + timedelta(hours=3)
        self.assertEqual(self.analyzer.age_bucket(future), "recent")

    def test_severity_helper_no_longer_exists(self):
        self.assertFalse(
            hasattr(self.analyzer, "adjust_severity_by_age"),
            "age must not be folded back into severity",
        )


class AgeDoesNotChangeCountsTests(unittest.TestCase):
    """End-to-end: an old critical event stays in the Critical count."""

    def test_hours_old_kernel_panic_is_still_counted_critical(self):
        old = datetime.now(timezone.utc) - timedelta(hours=6)
        stamp = old.strftime("%Y-%m-%dT%H:%M:%S+00:00")
        content = (
            "SYSTEM_CRITICAL_LOGS:\n"
            f"{stamp} leaf01 kernel: Out of memory: Killed process 900 (switchd)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            log_file = os.path.join(tmp, "leaf01_logs.txt")
            with open(log_file, "w", encoding="utf-8") as handle:
                handle.write(content)

            instance = analyzer(tmp)
            self.assertTrue(instance.process_device_logs("leaf01", log_file))

            counts = instance.log_counts["leaf01"]
            self.assertEqual(counts["critical"], 1, f"counts were {dict(counts)}")
            self.assertEqual(counts["info"], 0)

            entry = instance.log_analysis["leaf01"]["critical"][0]
            self.assertEqual(entry["severity"], "critical")
            self.assertEqual(entry["age"], "historical")
            self.assertNotIn("original_severity", entry)


class CsvExportContractTests(unittest.TestCase):
    """The CSV export must exclude rows the table-filter funnels hid.

    table-filter.js hides rows via the tf-hidden class, never via
    style.display, so the downloadCSV row predicate must check that class
    (alongside the log-details exclusion) or the export silently includes
    devices — and their full message dumps — the operator filtered out.
    """

    def test_the_download_predicate_excludes_tf_hidden_rows(self):
        source = (SCRIPT_DIR / "process_log_data.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "if (row.style.display !== 'none' &&\n"
            "                        !row.classList.contains('tf-hidden') &&\n"
            "                        !row.classList.contains('log-details')) {",
            source,
        )


if __name__ == "__main__":
    unittest.main()
