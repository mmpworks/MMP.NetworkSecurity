"""Tests for tools/gate_app.ps1, the decisions behind the gate's app steps. Run: python -I tools/test_gate_app.py

The functions are dot-sourced in pwsh and their results printed as JSON, so each case is a plain call with plain inputs.
"""
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent
LIB = TOOLS / "gate_app.ps1"


def ps(expr, cwd=None):
    r = subprocess.run(["pwsh", "-NoProfile", "-Command", f". '{LIB}'; ConvertTo-Json -Compress -Depth 4 -InputObject ({expr})"],
                       capture_output=True, text=True, cwd=cwd)
    if r.returncode != 0 or not r.stdout.strip():
        raise AssertionError(f"pwsh failed ({r.returncode}): {r.stdout}{r.stderr}")
    return json.loads(r.stdout)


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def plan(has_app=True, skip=False, reason="", lesson="", diff=0):
    return ps(f"Get-AppProofPlan -HasApp ${str(has_app).lower()} -SkipApp ${str(skip).lower()} -SkipAppReason '{reason}' "
              f"-Lesson '{lesson}' -AppDiffCount {diff}")


class Plan(unittest.TestCase):
    def test_no_app_folder_skips_by_name(self):
        p = plan(has_app=False)
        self.assertEqual(p["Mode"], "none")
        self.assertIn("app/package.json is absent", p["Why"])

    def test_skip_app_with_no_app_diff_skips(self):
        p = plan(skip=True, diff=0)
        self.assertEqual(p["Mode"], "skip")
        self.assertIn("-SkipApp", p["Why"])

    def test_skip_app_with_an_app_diff_and_no_reason_is_refused(self):
        p = plan(skip=True, diff=3)
        self.assertEqual(p["Mode"], "refuse")
        self.assertIn("APP_PROOF_SKIPPED", p["Why"])
        self.assertIn("3 files", p["Why"])
        self.assertIn("-SkipAppReason", p["Why"])

    def test_skip_app_with_an_app_diff_and_a_reason_skips_and_keeps_the_reason(self):
        p = plan(skip=True, diff=3, reason="docs-only edit under app/")
        self.assertEqual(p["Mode"], "skip")
        self.assertIn("docs-only edit under app/", p["Why"])

    def test_an_app_diff_runs_typecheck_build_and_the_full_suite(self):
        p = plan(diff=2)
        self.assertEqual(p["Mode"], "suite")
        self.assertTrue(p["Typecheck"] and p["Build"] and p["Suite"])
        self.assertEqual(p["Lesson"], "")

    def test_an_app_diff_with_a_lesson_narrows_the_suite_and_says_so(self):
        p = plan(diff=2, lesson="4")
        self.assertEqual(p["Mode"], "narrowed")
        self.assertEqual(p["Lesson"], "4")
        self.assertIn("narrowed by -Lesson 4", p["Label"])
        self.assertTrue(p["Typecheck"] and p["Build"])

    def test_no_app_diff_with_a_lesson_runs_typecheck_and_that_lesson(self):
        p = plan(diff=0, lesson="2")
        self.assertEqual(p["Mode"], "lesson")
        self.assertTrue(p["Typecheck"])
        self.assertTrue(p["Build"], "the preview serves app/dist, so a stale dist must not pass a lesson spec")
        self.assertEqual(p["Lesson"], "2")

    def test_no_app_diff_and_no_lesson_runs_typecheck_only(self):
        p = plan(diff=0)
        self.assertEqual(p["Mode"], "check")
        self.assertTrue(p["Typecheck"])
        self.assertFalse(p["Suite"])
        self.assertIn("no -Lesson given", p["Why"])


class RepoFacts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.tmp.name)
        git("init", "-q", "-b", "main", cwd=self.repo)
        git("config", "user.email", "t@example.com", cwd=self.repo)
        git("config", "user.name", "t", cwd=self.repo)
        (self.repo / "app").mkdir()
        (self.repo / "app" / "a.txt").write_text("a", encoding="utf-8")
        (self.repo / "tools.txt").write_text("t", encoding="utf-8")
        git("add", "-A", cwd=self.repo)
        git("commit", "-q", "-m", "init", cwd=self.repo)
        git("update-ref", "refs/remotes/origin/main", "HEAD", cwd=self.repo)

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self, rel, text):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        git("add", "-A", cwd=self.repo)
        git("commit", "-q", "-m", "change " + rel, cwd=self.repo)

    def count(self):
        return ps(f"Get-AppDiffCount -Repo '{self.repo}'")

    def head(self):
        return ps(f"Get-HeadLine -Repo '{self.repo}'")

    def test_head_line_is_the_short_sha_and_clean(self):
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=self.repo, capture_output=True, text=True).stdout.strip()
        self.assertEqual(self.head(), sha)

    def test_head_line_marks_a_tracked_edit_as_dirty(self):
        (self.repo / "tools.txt").write_text("changed", encoding="utf-8")
        self.assertTrue(self.head().endswith("+dirty"), self.head())

    def test_head_line_ignores_an_untracked_file(self):
        (self.repo / "scratch.log").write_text("x", encoding="utf-8")
        self.assertNotIn("dirty", self.head())

    def test_head_line_outside_a_repo_says_unknown(self):
        with tempfile.TemporaryDirectory() as other:
            self.assertEqual(ps(f"Get-HeadLine -Repo '{other}'"), "unknown")

    def test_no_app_change_counts_zero(self):
        self.commit("src/x.cs", "x")
        self.assertEqual(self.count(), 0)

    def test_a_committed_app_change_counts(self):
        self.commit("app/b.txt", "b")
        self.commit("app/c.txt", "c")
        self.commit("src/x.cs", "x")
        self.assertEqual(self.count(), 2)

    def test_an_uncommitted_app_edit_counts_too(self):
        (self.repo / "app" / "a.txt").write_text("edited", encoding="utf-8")
        self.assertEqual(self.count(), 1)

    def test_a_missing_origin_main_counts_as_changed_so_the_gate_cannot_skip_by_accident(self):
        git("update-ref", "-d", "refs/remotes/origin/main", cwd=self.repo)
        self.assertGreaterEqual(self.count(), 1)


class Tools(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = pathlib.Path(self.tmp.name) / "app"
        self.app.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def tree(self, *files):
        for rel in files:
            path = self.app / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("//", encoding="utf-8")

    def missing(self):
        return ps(f"@(Test-AppTools -AppDir '{self.app}')")

    def test_no_node_modules_names_the_command_to_run_and_installs_nothing(self):
        out = self.missing()
        self.assertTrue(any("TOOL_MISSING" in m and "npm ci" in m for m in out), out)
        self.assertFalse((self.app / "node_modules").exists())

    def test_a_missing_playwright_cli_is_named(self):
        self.tree("node_modules/vite/bin/vite.js")
        out = self.missing()
        self.assertTrue(any("@playwright/test/cli.js" in m for m in out), out)

    def test_a_complete_tree_reports_nothing_missing(self):
        self.tree("node_modules/vite/bin/vite.js", "node_modules/@playwright/test/cli.js")
        self.assertEqual(self.missing(), [])

    def test_a_broken_electron_install_is_named_with_the_fix(self):
        self.tree("node_modules/electron/index.js")
        (self.app / "node_modules" / "electron" / "index.js").write_text(
            "throw new Error('Electron failed to install correctly, please delete node_modules/electron and try installing again')", encoding="utf-8")
        out = ps(f"@(Test-ElectronBinary -AppDir '{self.app}')")
        self.assertTrue(any("TOOL_MISSING" in m and "ELECTRON_OVERRIDE_DIST_PATH" in m for m in out), out)

    def test_a_working_electron_install_reports_nothing(self):
        self.tree("node_modules/electron/index.js")
        (self.app / "node_modules" / "electron" / "index.js").write_text("module.exports = __filename", encoding="utf-8")  # a path that exists
        self.assertEqual(ps(f"@(Test-ElectronBinary -AppDir '{self.app}')"), [])

    # Jared's #277 review: electron/index.js only RETURNS a path (path.txt, or ELECTRON_OVERRIDE_DIST_PATH); it never checks the file exists.
    FAKE_INDEX = ("const path = require('path'); module.exports = path.join(process.env.ELECTRON_OVERRIDE_DIST_PATH || "
                  "path.join(__dirname, 'dist'), 'electron.exe')")

    def test_an_electron_path_with_no_file_behind_it_is_missing(self):
        self.tree("node_modules/electron/index.js")
        (self.app / "node_modules" / "electron" / "index.js").write_text(self.FAKE_INDEX, encoding="utf-8")
        out = ps(f"@(Test-ElectronBinary -AppDir '{self.app}')")
        self.assertTrue(any("TOOL_MISSING" in m and "ELECTRON_OVERRIDE_DIST_PATH" in m for m in out), out)

    def test_an_override_folder_that_is_empty_is_missing(self):
        self.tree("node_modules/electron/index.js")
        (self.app / "node_modules" / "electron" / "index.js").write_text(self.FAKE_INDEX, encoding="utf-8")
        empty = pathlib.Path(self.tmp.name) / "empty-dist"
        empty.mkdir()
        os.environ["ELECTRON_OVERRIDE_DIST_PATH"] = str(empty)
        try:
            out = ps(f"@(Test-ElectronBinary -AppDir '{self.app}')")
        finally:
            del os.environ["ELECTRON_OVERRIDE_DIST_PATH"]
        self.assertTrue(any("TOOL_MISSING" in m for m in out), out)

    def test_an_override_path_with_no_extension_is_ready_when_the_exe_exists(self):
        """With ELECTRON_OVERRIDE_DIST_PATH and no path.txt, electron/index.js returns <dist>/electron with no extension, and Windows starts
        <dist>/electron.exe. A probe that needs the exact name would fail the gate on a working setup (the real override on this machine)."""
        self.tree("node_modules/electron/index.js")
        (self.app / "node_modules" / "electron" / "index.js").write_text(
            "const path = require('path'); module.exports = path.join(process.env.ELECTRON_OVERRIDE_DIST_PATH, 'electron')", encoding="utf-8")
        dist = pathlib.Path(self.tmp.name) / "dist2"
        dist.mkdir()
        (dist / "electron.exe").write_text("MZ", encoding="utf-8")
        os.environ["ELECTRON_OVERRIDE_DIST_PATH"] = str(dist)
        try:
            out = ps(f"@(Test-ElectronBinary -AppDir '{self.app}')")
        finally:
            del os.environ["ELECTRON_OVERRIDE_DIST_PATH"]
        self.assertEqual(out, [])

    def test_an_electron_path_with_a_file_behind_it_is_ready(self):
        self.tree("node_modules/electron/index.js")
        (self.app / "node_modules" / "electron" / "index.js").write_text(self.FAKE_INDEX, encoding="utf-8")
        dist = pathlib.Path(self.tmp.name) / "dist"
        dist.mkdir()
        (dist / "electron.exe").write_text("MZ", encoding="utf-8")
        os.environ["ELECTRON_OVERRIDE_DIST_PATH"] = str(dist)
        try:
            out = ps(f"@(Test-ElectronBinary -AppDir '{self.app}')")
        finally:
            del os.environ["ELECTRON_OVERRIDE_DIST_PATH"]
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
