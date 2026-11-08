"""Tests for tools/githooks/pre-push through a real `git push` (Windows: the fake gh is a .cmd file).

Run: python -I tools/githooks/test_pre_push_guard.py
Each case builds a throwaway bare remote and clone, points core.hooksPath at this folder, puts a fake `gh` first on PATH, and checks whether
the push went through. The fake gh prints the JSON in FAKE_GH_JSON, or exits with FAKE_GH_EXIT.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

HOOKS = pathlib.Path(__file__).resolve().parent


def run(args, cwd, env=None, check=True):
    r = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise AssertionError(f"{args} failed: {r.stdout}{r.stderr}")
    return r


class RepoFixture(unittest.TestCase):
    """A throwaway bare remote, a clone with one commit on main and a commit on feat/x, and a fake gh first on PATH. Has no tests."""

    def install_hooks(self):
        run(["git", "config", "core.hooksPath", str(HOOKS)], self.work)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = pathlib.Path(self.tmp.name)
        self.remote, self.work, self.fake = base / "remote.git", base / "work", base / "fakebin"
        self.fake.mkdir()
        (self.fake / "gh.cmd").write_text('@echo off\r\nif defined FAKE_GH_EXIT exit /b %FAKE_GH_EXIT%\r\ntype "%FAKE_GH_JSON%"\r\n', encoding="ascii")
        self.json_file = base / "prs.json"
        run(["git", "init", "-q", "--bare", "-b", "main", str(self.remote)], base)
        run(["git", "clone", "-q", str(self.remote), str(self.work)], base)
        for k, v in (("user.email", "t@example.com"), ("user.name", "t")):
            run(["git", "config", k, v], self.work)
        self.install_hooks()
        (self.work / "a.txt").write_text("a", encoding="utf-8")
        run(["git", "add", "a.txt"], self.work)
        run(["git", "commit", "-q", "-m", "init"], self.work)
        run(["git", "branch", "-M", "main"], self.work)
        self.env = dict(os.environ, PATH=str(self.fake) + os.pathsep + os.environ["PATH"], FAKE_GH_JSON=str(self.json_file))
        self.env.pop("FAKE_GH_EXIT", None)
        self.push_ok("main")  # main goes first, with the hook skipping it, so branches have a base
        run(["git", "switch", "-q", "-c", "feat/x"], self.work)
        (self.work / "b.txt").write_text("b", encoding="utf-8")
        run(["git", "add", "b.txt"], self.work)
        run(["git", "commit", "-q", "-m", "work"], self.work)

    def tearDown(self):
        self.tmp.cleanup()

    def prs(self, *states):
        self.json_file.write_text(json.dumps([{"number": i + 1, "state": s} for i, s in enumerate(states)]), encoding="utf-8")

    def push(self, *refspec, env=None):
        return run(["git", "push", "-q", "origin", *refspec], self.work, env or self.env, check=False)

    def push_ok(self, *refspec):
        self.prs()
        r = self.push(*refspec)
        self.assertEqual(r.returncode, 0, r.stderr)

    def remote_has(self, branch):
        return bool(run(["git", "ls-remote", "--heads", str(self.remote), branch], self.work).stdout.strip())



class PrePushGuard(RepoFixture):
    """The rule, with core.hooksPath pointing straight at this folder."""

    def test_merged_pr_refuses_and_names_the_route(self):
        self.prs("MERGED")
        r = self.push("feat/x")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MERGED", r.stderr)
        self.assertIn("new name", r.stderr)
        self.assertFalse(self.remote_has("feat/x"))

    def test_closed_pr_refuses(self):
        self.prs("CLOSED")
        self.assertNotEqual(self.push("feat/x").returncode, 0)
        self.assertFalse(self.remote_has("feat/x"))

    def test_open_pr_allows(self):
        self.prs("OPEN")
        self.assertEqual(self.push("feat/x").returncode, 0)
        self.assertTrue(self.remote_has("feat/x"))

    def test_no_pr_allows_a_new_branch(self):
        self.prs()
        self.assertEqual(self.push("feat/x").returncode, 0)
        self.assertTrue(self.remote_has("feat/x"))

    def test_reused_name_with_a_new_open_pr_allows(self):
        self.prs("MERGED", "OPEN")
        self.assertEqual(self.push("feat/x").returncode, 0)

    def test_branch_delete_allows_even_when_merged(self):
        self.prs()
        self.assertEqual(self.push("feat/x").returncode, 0)
        self.prs("MERGED")
        self.assertEqual(self.push(":feat/x").returncode, 0)
        self.assertFalse(self.remote_has("feat/x"))

    def test_gh_failure_refuses(self):
        self.prs()
        r = self.push("feat/x", env=dict(self.env, FAKE_GH_EXIT="1"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("gh", r.stderr)
        self.assertFalse(self.remote_has("feat/x"))

    def test_a_tag_push_never_asks_gh(self):
        run(["git", "tag", "v0"], self.work)
        r = self.push("v0", env=dict(self.env, FAKE_GH_EXIT="1"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_main_push_is_not_this_hooks_business(self):
        run(["git", "switch", "-q", "main"], self.work)
        run(["git", "commit", "-q", "--allow-empty", "-m", "next"], self.work)
        r = self.push("main", env=dict(self.env, FAKE_GH_EXIT="1"))
        self.assertEqual(r.returncode, 0, r.stderr)


class InstalledHook(RepoFixture):
    """What tools/bootstrap.ps1 sets up: install.ps1 copies the hook into the shared git folder and sets an absolute core.hooksPath, so the
    hook runs whatever branch a worktree has checked out, including a branch made before the hook files existed."""

    def install_hooks(self):
        run(["pwsh", "-NoProfile", "-File", str(HOOKS / "install.ps1"), "-Repo", str(self.work)], self.work)

    def test_hooks_path_is_absolute_and_outside_the_working_tree(self):
        path = run(["git", "config", "core.hooksPath"], self.work).stdout.strip()
        self.assertTrue(pathlib.Path(path).is_absolute(), path)
        self.assertTrue((pathlib.Path(path) / "pre-push").is_file())
        self.assertFalse((self.work / "tools" / "githooks").exists(), "the probe branch must have no hook files of its own")

    def test_a_branch_without_the_hook_files_is_still_guarded(self):
        self.prs("MERGED")
        r = self.push("feat/x")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MERGED", r.stderr)
        self.assertFalse(self.remote_has("feat/x"))

    def test_a_second_worktree_is_guarded_too(self):
        wt = pathlib.Path(self.tmp.name) / "wt2"
        run(["git", "worktree", "add", "-q", "-b", "feat/y", str(wt), "main"], self.work)
        run(["git", "commit", "-q", "--allow-empty", "-m", "y"], wt)
        self.prs("CLOSED")
        r = run(["git", "push", "-q", "origin", "feat/y"], wt, self.env, check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("CLOSED", r.stderr)

    def test_installing_twice_keeps_the_copy_equal_to_the_source(self):
        run(["pwsh", "-NoProfile", "-File", str(HOOKS / "install.ps1"), "-Repo", str(self.work)], self.work)
        path = pathlib.Path(run(["git", "config", "core.hooksPath"], self.work).stdout.strip())
        for name in ("pre-push", "pre_push_guard.py"):
            self.assertEqual((path / name).read_bytes(), (HOOKS / name).read_bytes(), name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
