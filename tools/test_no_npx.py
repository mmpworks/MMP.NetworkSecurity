"""Tests for tools/no_npx.py. Run: python -I tools/test_no_npx.py"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "no_npx.py"


class NoNpx(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        for folder in ("tools", "app/scripts"):
            (self.root / folder).mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, rel, text):
        path = self.root / rel
        path.write_text(text, encoding="utf-8")

    def put_deep(self, rel, text):
        (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
        self.put(rel, text)

    def run_check(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--root", str(self.root)], capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def test_a_clean_tree_passes(self):
        self.put("tools/gate.ps1", "node node_modules/@playwright/test/cli.js test x\n")
        self.put("app/package.json", '{"scripts": {"e2e": "playwright test"}}\n')
        code, out = self.run_check()
        self.assertEqual(code, 0, out)

    def test_npx_in_a_gate_script_fails_and_names_file_and_line(self):
        self.put("tools/gate.ps1", "Step 'x' { npx playwright test }\n")
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("NPX_FOUND", out)
        self.assertIn("gate.ps1:1", out)

    def test_npx_in_a_package_json_script_fails(self):
        self.put("app/package.json", '{"scripts": {"e2e": "npx playwright test"}}\n')
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("package.json", out)

    def test_npx_cmd_and_a_node_script_spawn_fail(self):
        self.put("app/scripts/run.mjs", "spawn('npx', ['playwright'])\n")
        self.put("tools/other.ps1", "& npx.cmd tsc\n")
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("run.mjs:1", out)
        self.assertIn("other.ps1:1", out)

    def test_npx_in_an_app_config_file_fails(self):
        """playwright.config.ts starts the preview server for every e2e run, so it is scanned too (Jared, #271)."""
        self.put("app/playwright.config.ts", "webServer: [{ command: `npx vite preview --port 1` }]\n")
        self.put("app/vite.config.ts", "export default {}\n")
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("app/playwright.config.ts:1", out)

    def test_npx_in_acceptance_fails(self):
        """acceptance/ runs the e2e suite, so its scripts are scanned too (Echo, after #271)."""
        self.put_deep("acceptance/e2e/global-setup.ts", "spawn('npx', ['vite', 'preview'])\n")
        self.put_deep("acceptance/run.ps1", "Invoke-Tool 'node' @('x')\n")
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("acceptance/e2e/global-setup.ts:1", out)

    def test_npx_in_acceptance_csharp_fails(self):
        """acceptance/ clause code is C# and can start a process (Jared, #275)."""
        self.put_deep("acceptance/lib/Harness/Tools.cs", 'Proc.Start("npx", "playwright test");\n')
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("acceptance/lib/Harness/Tools.cs:1", out)

    def test_installed_packages_and_run_folders_are_skipped(self):
        self.put_deep("acceptance/e2e/node_modules/pkg/cli.js", "spawn('npx')\n")
        self.put_deep("acceptance/.work/run-1/e2e/state.json", '{"note": "npx"}\n')
        self.put_deep("acceptance/e2e/test-results/x.json", '{"note": "npx"}\n')
        self.put_deep("tools/node_modules/pkg/index.js", "npx\n")
        code, out = self.run_check()
        self.assertEqual(code, 0, out)

    def test_a_word_that_only_contains_npx_passes(self):
        self.put("tools/gate.ps1", "# unpxfoo and npxx are not the tool\n")
        code, out = self.run_check()
        self.assertEqual(code, 0, out)

    def test_the_check_and_its_test_may_name_the_tool(self):
        self.put("tools/no_npx.py", "# npx\n")
        self.put("tools/test_no_npx.py", "# npx\n")
        code, out = self.run_check()
        self.assertEqual(code, 0, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
