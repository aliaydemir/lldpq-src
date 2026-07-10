#!/usr/bin/env python3
"""Static contracts for lightweight per-analyzer timing output."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MONITOR = (ROOT / "lldpq/monitor.sh").read_text(encoding="utf-8")
WRAPPER = (ROOT / "bin/lldpq").read_text(encoding="utf-8")


class AnalyzerTimingContractTests(unittest.TestCase):
    def test_each_parallel_job_records_its_own_elapsed_time(self):
        section = MONITOR.split("analysis_log_dir=", 1)[1].split(
            "validate_analysis_outputs()", 1
        )[0]
        self.assertIn("declare -a analysis_timing_files=()", section)
        self.assertIn("started=$(analysis_now_ms)", section)
        self.assertIn('"$@"', section)
        self.assertIn("status=$?", section)
        self.assertIn("finished=$(analysis_now_ms)", section)
        self.assertIn('"$((finished - started))"', section)

    def test_summary_is_not_gated_by_deep_device_timing(self):
        output = MONITOR.split('echo "Analyzer timings (parallel):"', 1)[1].split(
            "analyzer_jobs_end=", 1
        )[0]
        self.assertNotIn("MONITOR_TIMING", output)
        self.assertIn("%-12s %d.%03ds", output)
        self.assertIn("analysis_timing_files", output)
        self.assertIn("__LLDPQ_ANALYZER_TIMING__", output)
        self.assertIn("phases: %s", output)

    def test_subphase_instrumentation_is_enabled_inside_analyzer_job(self):
        section = MONITOR.split("start_analysis() {", 1)[1].split(
            "validate_analysis_outputs()", 1
        )[0]
        self.assertIn('LLDPQ_ANALYZER_TIMING=1 "$@"', section)

    def test_existing_verbose_flag_controls_visibility(self):
        self.assertIn("-) QUIET=false", WRAPPER)
        self.assertIn('"$@" >/dev/null 2>&1', WRAPPER)
        self.assertIn("per-analyzer timing", WRAPPER)


if __name__ == "__main__":
    unittest.main()
