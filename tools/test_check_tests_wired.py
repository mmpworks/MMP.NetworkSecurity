"""Tests for tools/check_tests_wired.py: every tools/**/test_*.py needs a step in tools/gate.ps1.
Run: python -I tools/test_check_tests_wired.py
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "check_tests_wired.py"


class TestsWired(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "tools").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, rel, text="x"):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def run_check(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--root", str(self.root)], capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def test_every_test_file_with_a_step_passes(self):
        self.put("tools/test_a.py")
        self.put("tools/githooks/test_b.py")
        self.put("tools/gate.ps1", "Step 'a tests' { python -I tools/test_a.py }\nStep 'b tests' { python -I tools/githooks/test_b.py }\n")
        code, out = self.run_check()
        self.assertEqual(code, 0, out)

    def test_a_test_file_with_no_step_fails_and_names_the_file_and_the_line_to_add(self):
        self.put("tools/test_a.py")
        self.put("tools/test_orphan.py")
        self.put("tools/gate.ps1", "Step 'a tests' { python -I tools/test_a.py }\n")
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("TEST_UNWIRED", out)
        self.assertIn("tools/test_orphan.py", out)
        self.assertIn("Step", out)
        self.assertNotIn("tools/test_a.py has no", out)

    def test_a_nested_test_file_with_no_step_fails(self):
        self.put("tools/githooks/test_deep.py")
        self.put("tools/gate.ps1", "# nothing\n")
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("tools/githooks/test_deep.py", out)

    def test_a_name_only_in_a_comment_does_not_count_as_a_step(self):
        self.put("tools/test_a.py")
        self.put("tools/gate.ps1", "# python -I tools/test_a.py is run elsewhere\n")
        code, out = self.run_check()
        self.assertEqual(code, 1, out)

    def test_a_file_that_is_not_named_test_is_ignored(self):
        self.put("tools/helper.py")
        self.put("tools/gate.ps1", "# nothing\n")
        code, out = self.run_check()
        self.assertEqual(code, 0, out)

    def test_a_missing_gate_is_its_own_failure(self):
        self.put("tools/test_a.py")
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("gate.ps1", out)

    def test_a_longer_name_does_not_stand_in_for_a_shorter_one(self):
        self.put("tools/test_a.py")
        self.put("tools/gate.ps1", "Step 'x' { python -I tools/test_a.py.bak }\nStep 'y' { python -I tools/other_test_a.py }\n")
        code, out = self.run_check()
        self.assertEqual(code, 1, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
