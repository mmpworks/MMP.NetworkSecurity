"""Tests for app/scripts/dist-stamp.cjs: app/dist remembers the commit it was built from, and every entry point that serves it refuses a stale one.
Run: python -I tools/test_dist_stamp.py
"""
import json
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "app" / "scripts" / "dist-stamp.cjs"


def run(*args, cwd=None):
    return subprocess.run(list(args), cwd=cwd, capture_output=True, text=True)


def git(*args, cwd):
    r = run("git", *args, cwd=cwd)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


class DistStamp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = pathlib.Path(self.tmp.name)
        git("init", "-q", "-b", "main", cwd=self.repo)
        git("config", "user.email", "t@example.com", cwd=self.repo)
        git("config", "user.name", "t", cwd=self.repo)
        (self.repo / "app" / "dist").mkdir(parents=True)
        (self.repo / "app" / "src").mkdir()
        (self.repo / "app" / "src" / "a.ts").write_text("a", encoding="utf-8")
        (self.repo / "top.txt").write_text("t", encoding="utf-8")
        git("add", "-A", cwd=self.repo)
        git("commit", "-q", "-m", "init", cwd=self.repo)
        (self.repo / "app" / "dist" / "index.html").write_text("<html>", encoding="utf-8")   # ignored in the real repo; here never added

    def tearDown(self):
        self.tmp.cleanup()

    def stamp(self, mode):
        return run("node", str(SCRIPT), mode, "--root", str(self.repo), "--dist", str(self.repo / "app" / "dist"))

    def commit(self, rel, text):
        (self.repo / rel).write_text(text, encoding="utf-8")
        git("add", "-A", ":!app/dist", cwd=self.repo)
        git("commit", "-q", "-m", "change " + rel, cwd=self.repo)

    def test_a_fresh_build_passes(self):
        self.assertEqual(self.stamp("write").returncode, 0)
        r = self.stamp("check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_new_commit_after_the_build_is_refused_by_name(self):
        self.stamp("write")
        self.commit("app/src/a.ts", "changed")
        r = self.stamp("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("DIST_STALE", r.stdout + r.stderr)
        self.assertIn("npm run build", r.stdout + r.stderr)

    def test_switching_to_another_branch_is_refused_and_switching_back_passes(self):
        self.stamp("write")
        git("switch", "-q", "-c", "other", cwd=self.repo)
        self.commit("app/src/b.ts", "b")
        r = self.stamp("check")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("DIST_STALE", r.stdout + r.stderr)
        git("switch", "-q", "main", cwd=self.repo)
        self.assertEqual(self.stamp("check").returncode, 0)

    def test_an_edit_to_a_tracked_app_file_after_the_build_is_refused(self):
        self.stamp("write")
        (self.repo / "app" / "src" / "a.ts").write_text("edited after the build", encoding="utf-8")
        r = self.stamp("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("DIST_STALE", r.stdout + r.stderr)

    def test_a_build_made_with_edits_passes_until_the_edits_change(self):
        (self.repo / "app" / "src" / "a.ts").write_text("edit one", encoding="utf-8")
        self.stamp("write")
        self.assertEqual(self.stamp("check").returncode, 0)
        (self.repo / "app" / "src" / "a.ts").write_text("edit two", encoding="utf-8")
        self.assertEqual(self.stamp("check").returncode, 1)

    def test_an_uncommitted_edit_outside_app_does_not_make_the_build_stale(self):
        self.stamp("write")
        (self.repo / "top.txt").write_text("edited outside app", encoding="utf-8")
        self.assertEqual(self.stamp("check").returncode, 0)

    def test_a_missing_dist_is_named(self):
        r = run("node", str(SCRIPT), "check", "--root", str(self.repo), "--dist", str(self.repo / "app" / "nope"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("DIST_MISSING", r.stdout + r.stderr)

    def test_a_dist_with_no_stamp_is_named(self):
        r = self.stamp("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("DIST_UNSTAMPED", r.stdout + r.stderr)
        self.assertIn("npm run build", r.stdout + r.stderr)

    def test_outside_a_git_repo_the_check_cannot_judge_and_says_so(self):
        with tempfile.TemporaryDirectory() as other:
            dist = pathlib.Path(other) / "app" / "dist"
            dist.mkdir(parents=True)
            (dist / "index.html").write_text("x", encoding="utf-8")
            w = run("node", str(SCRIPT), "write", "--root", other, "--dist", str(dist))
            self.assertEqual(w.returncode, 0, w.stderr)
            r = run("node", str(SCRIPT), "check", "--root", other, "--dist", str(dist))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("unchecked", r.stdout + r.stderr)

    def test_the_stamp_file_records_the_commit_and_the_app_tree_and_lives_in_dist(self):
        self.stamp("write")
        data = json.loads((self.repo / "app" / "dist" / ".build-commit.json").read_text(encoding="utf-8"))
        self.assertEqual(data["commit"], git("rev-parse", "HEAD", cwd=self.repo))
        self.assertEqual(data["tree"], git("rev-parse", "HEAD:app", cwd=self.repo))

    # Jared's #307 review: the build's inputs are all under app/, so the stamp keys on the app/ tree id. A commit that leaves app/ alone
    # (a run log, a Host fix, a doc) must not make dist stale, or agents hit a steady false stop.
    def test_a_commit_that_leaves_app_alone_does_not_make_dist_stale(self):
        self.stamp("write")
        self.commit("top.txt", "a run log or a doc changed")
        r = self.stamp("check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_commit_that_adds_a_file_outside_app_does_not_make_dist_stale(self):
        self.stamp("write")
        (self.repo / "docs").mkdir()
        self.commit("docs/_run.md", "run log")
        self.assertEqual(self.stamp("check").returncode, 0)

    def test_another_branch_with_the_same_app_tree_passes(self):
        self.stamp("write")
        git("switch", "-q", "-c", "docs-only", cwd=self.repo)
        self.commit("top.txt", "docs-only branch")
        self.assertEqual(self.stamp("check").returncode, 0)

    def test_the_stale_message_prints_commits_for_people_to_read(self):
        self.stamp("write")
        built = git("rev-parse", "--short", "HEAD", cwd=self.repo)
        self.commit("app/src/a.ts", "app changed")
        now = git("rev-parse", "--short", "HEAD", cwd=self.repo)
        r = self.stamp("check")
        self.assertIn(built, r.stdout + r.stderr)
        self.assertIn(now, r.stdout + r.stderr)

    def test_a_stamp_from_before_the_tree_key_existed_is_unstamped_not_trusted(self):
        (self.repo / "app" / "dist" / ".build-commit.json").write_text(
            json.dumps({"commit": git("rev-parse", "HEAD", cwd=self.repo), "diff": ""}), encoding="utf-8")
        r = self.stamp("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("DIST_UNSTAMPED", r.stdout + r.stderr)


class WiredIn(unittest.TestCase):
    """The build writes the stamp, and the entry points that serve dist check it."""

    ROOT = pathlib.Path(__file__).resolve().parent.parent

    def test_the_build_script_writes_the_stamp(self):
        scripts = json.loads((self.ROOT / "app" / "package.json").read_text(encoding="utf-8"))["scripts"]
        self.assertIn("dist-stamp.cjs write", scripts["build"])

    def test_the_playwright_config_checks_the_stamp(self):
        self.assertIn("dist-stamp", (self.ROOT / "app" / "playwright.config.ts").read_text(encoding="utf-8"))

    def test_the_electron_main_process_checks_the_stamp(self):
        self.assertIn("dist-stamp", (self.ROOT / "app" / "electron" / "main.cjs").read_text(encoding="utf-8"))

    def test_the_launcher_rebuilds_a_stale_dist(self):
        self.assertIn("dist-stamp", (self.ROOT / "tools" / "open-app.ps1").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
