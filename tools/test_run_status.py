"""Tests for tools/run_status.py. Run: python -I tools/test_run_status.py"""
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "run_status.py"

GATE_START = "== layer_check\n== secret_guard\n== dotnet build src/NetSec.Core\n== dotnet test net10.0\n"
GATE_PASS = GATE_START + "gate Slice: 24 of 24 steps passed; report at docs/_runs/x.md\ngate exit 0\n"
GATE_FAIL = GATE_START + "gate Slice: 22 of 24 steps passed; report at docs/_runs/x.md\ngate exit 1\n"
PLAYWRIGHT_PASS = "Running 190 tests using 1 worker\n  ok 1 e2e\\a.spec.ts:3:5 > x (1.0s)\n\n  190 passed (23.5m)\n"
PLAYWRIGHT_FAIL = "  x  8 e2e\\b.spec.ts:69:7 > y (15.4s)\n\n  42 failed\n    e2e\\b.spec.ts:69:7 > y\n  23 did not run\n  111 passed (25.5m)\n"
PLAYWRIGHT_RUN = "Running 190 tests using 1 worker\n  ok   1 e2e\\a.spec.ts:3:5 > first (1.0s)\n  ok   2 e2e\\a.spec.ts:9:5 > second (2.0s)\n"
DOTNET_PASS = "Passed!  - Failed:     0, Passed:   255, Skipped:     0, Total:   255, Duration: 39 s - NetSec.Host.Tests.dll (net10.0)\n"
DOTNET_FAIL = "  Failed NetSec.Host.Tests.HostFlagTests.A_bad_flag [5 s]\nFailed!  - Failed:     1, Passed:   247, Skipped:     0, Total:   248, Duration: 37 s - X.dll (net10.0)\n"


class RunStatus(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def status(self, text, age_minutes=0, extra=()):
        path = pathlib.Path(self.tmp.name) / "run.log"
        path.write_text(text, encoding="utf-8")
        stamp = time.time() - age_minutes * 60
        os.utime(path, (stamp, stamp))
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), str(path), *extra], capture_output=True, text=True)
        return r.returncode, r.stdout.strip()

    def test_gate_passed(self):
        code, out = self.status(GATE_PASS)
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("PASSED"), out)
        self.assertIn("24 of 24", out)

    def test_gate_failed_names_the_counts(self):
        code, out = self.status(GATE_FAIL)
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("FAILED"), out)
        self.assertIn("22 of 24", out)

    def test_gate_running_names_the_current_step(self):
        code, out = self.status(GATE_START, age_minutes=1)
        self.assertEqual(code, 2)
        self.assertTrue(out.startswith("RUNNING"), out)
        self.assertIn("dotnet test net10.0", out)

    def test_gate_quiet_too_long_is_stuck_and_names_the_step(self):
        code, out = self.status(GATE_START, age_minutes=30)
        self.assertEqual(code, 3)
        self.assertTrue(out.startswith("STUCK"), out)
        self.assertIn("dotnet test net10.0", out)
        self.assertIn("30", out)

    def test_stuck_after_is_adjustable(self):
        code, _ = self.status(GATE_START, age_minutes=30, extra=("--stuck-after", "60"))
        self.assertEqual(code, 2)

    def test_playwright_passed(self):
        code, out = self.status(PLAYWRIGHT_PASS)
        self.assertEqual(code, 0)
        self.assertIn("190 passed", out)

    def test_playwright_failed_counts_failed_and_not_run(self):
        code, out = self.status(PLAYWRIGHT_FAIL)
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("FAILED"), out)
        self.assertIn("42 failed", out)
        self.assertIn("23 did not run", out)

    def test_playwright_running_counts_finished_specs(self):
        code, out = self.status(PLAYWRIGHT_RUN, age_minutes=1)
        self.assertEqual(code, 2)
        self.assertIn("2", out)

    def test_dotnet_passed(self):
        code, out = self.status(DOTNET_PASS)
        self.assertEqual(code, 0)
        self.assertIn("255 of 255", out)

    def test_dotnet_failed(self):
        code, out = self.status(DOTNET_FAIL)
        self.assertEqual(code, 1)
        self.assertIn("247 of 248", out)

    # Jared's #265 review: three logs that read PASSED while the run was still going, or after a framework failed.
    def test_a_gate_log_holding_an_inner_dotnet_result_is_still_running(self):
        text = ("== layer_check\n== dotnet test net10.0\nTest run for E:\\x\\NetSec.Tests.dll (.NETCoreApp,Version=v10.0)\n"
                "Passed!  - Failed:     0, Passed:   782, Skipped:     0, Total:   782, Duration: 9 s - NetSec.Tests.dll (net10.0)\n"
                "== dotnet test net48 (CF binaries)\n")
        code, out = self.status(text, age_minutes=1)
        self.assertEqual(code, 2, out)
        self.assertTrue(out.startswith("RUNNING"), out)
        self.assertIn("dotnet test net48", out)

    def test_a_gate_log_with_an_exit_line_and_no_summary_follows_the_exit_code(self):
        code, out = self.status("== layer_check\ngate exit 1\n")
        self.assertEqual(code, 1, out)

    def test_two_frameworks_one_failed_reads_failed_with_summed_counts(self):
        text = ("Test run for E:\\x\\net10.0\\NetSec.Tests.dll (.NETCoreApp,Version=v10.0)\n"
                "Passed!  - Failed:     0, Passed:    35, Skipped:     0, Total:    35, Duration: 1 s - NetSec.Tests.dll (net10.0)\n"
                "Test run for E:\\x\\net48\\NetSec.Tests.dll (.NETFramework,Version=v4.8)\n"
                "Failed!  - Failed:     2, Passed:    33, Skipped:     0, Total:    35, Duration: 1 s - NetSec.Tests.dll (net48)\n")
        code, out = self.status(text)
        self.assertEqual(code, 1, out)
        self.assertTrue(out.startswith("FAILED"), out)
        self.assertIn("68 of 70", out)
        self.assertIn("2 failed", out)

    def test_two_frameworks_announced_and_one_result_is_still_running(self):
        text = ("Test run for E:\\x\\net10.0\\NetSec.Tests.dll (.NETCoreApp,Version=v10.0)\n"
                "Passed!  - Failed:     0, Passed:    35, Skipped:     0, Total:    35, Duration: 1 s - NetSec.Tests.dll (net10.0)\n"
                "Test run for E:\\x\\net48\\NetSec.Tests.dll (.NETFramework,Version=v4.8)\n")
        code, out = self.status(text, age_minutes=1)
        self.assertEqual(code, 2, out)
        self.assertIn("1 of 2", out)

    def test_two_frameworks_both_passed_sums_the_counts(self):
        text = ("Test run for E:\\x\\net10.0\\a.dll (.NETCoreApp,Version=v10.0)\n"
                "Passed!  - Failed:     0, Passed:    35, Skipped:     0, Total:    35, Duration: 1 s - a.dll (net10.0)\n"
                "Test run for E:\\x\\net48\\a.dll (.NETFramework,Version=v4.8)\n"
                "Passed!  - Failed:     0, Passed:    35, Skipped:     0, Total:    35, Duration: 1 s - a.dll (net48)\n")
        code, out = self.status(text)
        self.assertEqual(code, 0, out)
        self.assertIn("70 of 70", out)

    def test_a_missing_log_is_its_own_answer(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), str(pathlib.Path(self.tmp.name) / "nope.log")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 4)
        self.assertTrue(r.stdout.startswith("NO_LOG"), r.stdout)

    def test_an_empty_log_that_is_old_is_stuck(self):
        code, out = self.status("", age_minutes=30)
        self.assertEqual(code, 3)
        self.assertTrue(out.startswith("STUCK"), out)

    def test_an_ansi_coloured_summary_still_parses(self):
        code, out = self.status("\x1b[32m  190 passed\x1b[39m (23.5m)\n")
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
