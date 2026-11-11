"""Tests for tools/check_acceptance_scope.py: a PR that changes acceptance/ may touch only acceptance/ and docs/.
Run: python -I tools/test_check_acceptance_scope.py
"""
import pathlib
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # tools/, for the shared temp folder (#400)
from tempdir import TempDir  # noqa: E402

SCRIPT = pathlib.Path(__file__).resolve().parent / "check_acceptance_scope.py"


def git(*args, cwd):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


class AcceptanceScope(unittest.TestCase):
    def setUp(self):
        self.tmp = TempDir()
        self.repo = pathlib.Path(self.tmp.name)
        git("init", "-q", "-b", "main", cwd=self.repo)
        git("config", "user.email", "t@example.com", cwd=self.repo)
        git("config", "user.name", "t", cwd=self.repo)
        for rel in ("acceptance/PIN", "acceptance/run.ps1", "docs/a.md", "tools/x.py", "app/x.ts", "src/s.cs"):
            self.write(rel, "base")
        git("add", "-A", cwd=self.repo)
        git("commit", "-q", "-m", "init", cwd=self.repo)
        git("update-ref", "refs/remotes/origin/main", "HEAD", cwd=self.repo)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, text):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def commit(self, *rels, text="changed"):
        for rel in rels:
            self.write(rel, text)
        git("add", *rels, cwd=self.repo)
        git("commit", "-q", "-m", "change " + ",".join(rels), cwd=self.repo)

    def check(self, *extra):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--root", str(self.repo), *extra], capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def test_nothing_changed_against_the_base_reads_skip_not_a_quiet_pass(self):
        """Run after a merge, origin/main...HEAD is empty and the check judged nothing (Jared, #353)."""
        code, out = self.check()
        self.assertEqual(code, 0, out)
        self.assertTrue(out.startswith("SKIP:"), out)

    def test_a_base_ref_judges_the_merge_that_origin_main_already_holds(self):
        self.commit("acceptance/run.ps1", "tools/x.py")
        git("update-ref", "refs/remotes/origin/main", "HEAD", cwd=self.repo)         # the merge landed: origin/main now equals HEAD
        code, out = self.check("--base", "HEAD~1")
        self.assertEqual(code, 1, out)
        self.assertIn("tools/x.py", out)

    def test_an_unknown_base_ref_fails_closed(self):
        code, out = self.check("--base", "no-such-ref")
        self.assertEqual(code, 1, out)
        self.assertIn("ACCEPTANCE_SCOPE", out)

    def test_acceptance_and_docs_pass(self):
        self.commit("acceptance/run.ps1", "docs/a.md")
        code, out = self.check()
        self.assertEqual(code, 0, out)

    def test_acceptance_plus_a_tools_file_fails_and_names_it(self):
        self.commit("acceptance/run.ps1", "tools/x.py")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("ACCEPTANCE_SCOPE", out)
        self.assertIn("tools/x.py", out)
        self.assertNotIn("acceptance/run.ps1 is", out, "files inside acceptance/ are not named as offenders")

    def test_acceptance_plus_a_new_top_folder_fails(self):
        self.commit("acceptance/run.ps1", "newfolder/y.txt")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("newfolder/y.txt", out)

    def test_every_outside_path_is_named(self):
        self.commit("acceptance/run.ps1", "tools/x.py", "app/x.ts", "src/s.cs")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        for path in ("tools/x.py", "app/x.ts", "src/s.cs"):
            self.assertIn(path, out)

    def test_renaming_an_app_file_into_acceptance_fails_on_the_app_path(self):
        git("mv", "app/x.ts", "acceptance/x.ts", cwd=self.repo)
        git("commit", "-q", "-m", "move", cwd=self.repo)
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("app/x.ts", out)

    def test_a_staged_rename_from_app_into_acceptance_fails_too(self):
        git("mv", "app/x.ts", "acceptance/x.ts", cwd=self.repo)
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("app/x.ts", out)

    def test_an_uncommitted_mixed_edit_fails(self):
        self.commit("acceptance/run.ps1")
        self.write("tools/x.py", "edited, not committed")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("tools/x.py", out)

    def test_an_untracked_file_outside_counts(self):
        self.commit("acceptance/run.ps1")
        self.write("scratch/new.txt", "untracked")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("scratch/new.txt", out)

    def test_a_change_with_no_acceptance_file_passes_whatever_it_touches(self):
        self.commit("app/x.ts", "tools/x.py", "src/s.cs")
        code, out = self.check()
        self.assertEqual(code, 0, out)

    def test_the_pin_alone_passes(self):
        self.commit("acceptance/PIN")
        code, out = self.check()
        self.assertEqual(code, 0, out)

    def test_an_unknown_origin_main_fails_closed(self):
        git("update-ref", "-d", "refs/remotes/origin/main", cwd=self.repo)
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("origin/main", out)

    # Jared's #319 nit: a failing git call must not come back as an empty file set (which would pass).
    def test_a_failing_git_diff_fails_closed_with_a_named_code(self):
        git("checkout", "-q", "--orphan", "unborn", cwd=self.repo)         # HEAD names no commit: `git diff origin/main...HEAD` exits 128
        git("rm", "-rq", "--cached", ".", cwd=self.repo)
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("ACCEPTANCE_SCOPE_GIT_FAILED", out)
        self.assertIn("diff", out)

    def test_a_failing_git_status_fails_closed_with_a_named_code(self):
        self.commit("acceptance/run.ps1")
        (self.repo / ".git" / "index").write_bytes(b"not an index")        # a broken index: `git status` exits 128
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("ACCEPTANCE_SCOPE_GIT_FAILED", out)

    def test_no_change_at_all_passes(self):
        code, out = self.check()
        self.assertEqual(code, 0, out)

    def test_a_deleted_acceptance_file_plus_an_outside_edit_fails(self):
        git("rm", "-q", "acceptance/run.ps1", cwd=self.repo)
        git("commit", "-q", "-m", "delete", cwd=self.repo)
        self.commit("tools/x.py")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("tools/x.py", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
