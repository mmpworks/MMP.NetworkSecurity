"""Tests for tools/githooks/pre-push through a real `git push` (Windows: the fake gh is a .cmd file).

Run: python -I tools/githooks/test_pre_push_guard.py
Each case builds a throwaway bare remote and clone, points core.hooksPath at this folder, puts a fake `gh` first on PATH, and checks whether
the push went through. The fake gh prints the JSON in FAKE_GH_JSON, or exits with FAKE_GH_EXIT.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))  # tools/, for the shared temp folder (#400)
from tempdir import TempDir  # noqa: E402

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

    def make_hooks_ref(self, name, overrides=None):
        """A branch `name` in the work clone, cut from main, whose tools/githooks holds the real hook files (overrides: {file: text}).
        It stands in for origin/main in the install and drift tests, because the installed copy comes from main, not from the working tree."""
        wt = pathlib.Path(self.tmp.name) / ("hooks-" + name)
        run(["git", "worktree", "add", "-q", "-b", name, str(wt), "main"], self.work)
        folder = wt / "tools" / "githooks"
        folder.mkdir(parents=True)
        for file in ("pre-push", "pre_push_guard.py"):
            shutil.copy(HOOKS / file, folder / file)
        for file, text in (overrides or {}).items():
            (folder / file).write_text(text, encoding="utf-8", newline="\n")
        run(["git", "add", "-A"], wt)
        run(["git", "commit", "-q", "-m", "hooks " + name], wt)

    def blob(self, ref, file):
        return subprocess.run(["git", "show", f"{ref}:tools/githooks/{file}"], cwd=self.work, capture_output=True, check=True).stdout

    def setUp(self):
        self.tmp = TempDir()
        base = pathlib.Path(self.tmp.name)
        self.remote, self.work, self.fake = base / "remote.git", base / "work", base / "fakebin"
        self.fake.mkdir()
        (self.fake / "gh.cmd").write_text('@echo off\r\nif defined FAKE_GH_EXIT exit /b %FAKE_GH_EXIT%\r\ntype "%FAKE_GH_JSON%"\r\n', encoding="ascii")
        self.json_file = base / "prs.json"
        run(["git", "init", "-q", "--bare", "-b", "main", str(self.remote)], base)
        run(["git", "clone", "-q", str(self.remote), str(self.work)], base)
        for k, v in (("user.email", "t@example.com"), ("user.name", "t")):
            run(["git", "config", k, v], self.work)
        (self.work / "a.txt").write_text("a", encoding="utf-8")
        run(["git", "add", "a.txt"], self.work)
        run(["git", "commit", "-q", "-m", "init"], self.work)
        run(["git", "branch", "-M", "main"], self.work)
        self.env = dict(os.environ, PATH=str(self.fake) + os.pathsep + os.environ["PATH"], FAKE_GH_JSON=str(self.json_file))
        self.env.pop("FAKE_GH_EXIT", None)
        self.push_ok("main")  # main goes first, so branches have a base
        self.install_hooks()  # after main exists: the install tests build a hooks branch from it
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


class ForcedPush(RepoFixture):
    """A rebase is pushed with --force-with-lease, not as a fast-forward, and that is how most stranded pushes happen. The hook must fire on it."""

    def remote_tip(self, branch):
        return run(["git", "ls-remote", "--heads", str(self.remote), branch], self.work).stdout.split()[0]

    def test_force_with_lease_to_a_merged_branch_is_refused(self):
        self.prs()
        self.assertEqual(self.push("feat/x").returncode, 0)
        tip = self.remote_tip("feat/x")
        run(["git", "switch", "-q", "-C", "feat/x", "main"], self.work)             # a rebased branch: same name, history no longer a descendant
        run(["git", "commit", "-q", "--allow-empty", "-m", "rebased"], self.work)
        self.prs("MERGED")
        plain = self.push("feat/x")
        self.assertNotEqual(plain.returncode, 0)
        self.assertNotIn("PRE-PUSH GUARD", plain.stderr)                              # git itself rejects a non-fast-forward before any hook
        for flag in (f"--force-with-lease=feat/x:{tip}", "--force"):
            r = self.push(flag, "feat/x")
            self.assertNotEqual(r.returncode, 0, flag)
            self.assertIn("PRE-PUSH GUARD", r.stderr, flag)
            self.assertIn("MERGED", r.stderr, flag)
            self.assertEqual(self.remote_tip("feat/x"), tip, flag)

    def test_force_with_lease_to_a_branch_with_an_open_pr_still_works(self):
        self.prs()
        self.assertEqual(self.push("feat/x").returncode, 0)
        tip = self.remote_tip("feat/x")
        run(["git", "switch", "-q", "-C", "feat/x", "main"], self.work)
        run(["git", "commit", "-q", "--allow-empty", "-m", "rebased"], self.work)
        self.prs("OPEN")
        r = self.push(f"--force-with-lease=feat/x:{tip}", "feat/x")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotEqual(self.remote_tip("feat/x"), tip)


def pwsh_script(script, *args, cwd=None):
    return run(["pwsh", "-NoProfile", "-File", str(script), *args], cwd, check=False)


class InstalledHook(RepoFixture):
    """What tools/bootstrap.ps1 sets up: install.ps1 copies the hook from main (here: the branch `hooksrc` stands in for origin/main) into the
    shared git folder and sets an absolute core.hooksPath, so the hook runs whatever branch a worktree has checked out, including a branch made
    before the hook files existed."""

    def install_hooks(self):
        self.make_hooks_ref("hooksrc")
        r = pwsh_script(HOOKS / "install.ps1", "-Repo", str(self.work), "-Ref", "hooksrc", cwd=self.work)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

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

    def test_installing_twice_keeps_the_copy_equal_to_main(self):
        r = pwsh_script(HOOKS / "install.ps1", "-Repo", str(self.work), "-Ref", "hooksrc", cwd=self.work)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        path = pathlib.Path(run(["git", "config", "core.hooksPath"], self.work).stdout.strip())
        for name in ("pre-push", "pre_push_guard.py"):
            self.assertEqual((path / name).read_bytes(), self.blob("hooksrc", name), name)

    def test_installing_from_a_branch_with_an_older_guard_does_not_downgrade_the_shared_copy(self):
        """The script is run from a folder holding an OLDER guard, as a builder on an old branch would; the copy still comes from main."""
        old = pathlib.Path(self.tmp.name) / "oldbranch"
        old.mkdir()
        shutil.copy(HOOKS / "install.ps1", old / "install.ps1")
        (old / "pre_push_guard.py").write_text("# an older guard\n", encoding="utf-8")
        (old / "pre-push").write_text("#!/bin/sh\n", encoding="utf-8")
        r = pwsh_script(old / "install.ps1", "-Repo", str(self.work), "-Ref", "hooksrc", cwd=self.work)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        path = pathlib.Path(run(["git", "config", "core.hooksPath"], self.work).stdout.strip())
        self.assertEqual((path / "pre_push_guard.py").read_bytes(), self.blob("hooksrc", "pre_push_guard.py"))
        self.assertNotIn(b"an older guard", (path / "pre_push_guard.py").read_bytes())

    def test_a_ref_without_the_guard_refuses_to_install(self):
        r = pwsh_script(HOOKS / "install.ps1", "-Repo", str(self.work), "-Ref", "main", cwd=self.work)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("tools/githooks", r.stdout + r.stderr)


class DriftCheck(RepoFixture):
    """check-installed.ps1, the gate step that fails when the installed hook is missing or differs from MAIN's tools/githooks (Jared, #257, #261).
    The reference is main, never the working tree: a builder on an older branch must not be told to install an older guard over the shared copy.
    Branches stand in for origin/main: `hooksrc` is main's guard, `newer` is main after a later guard change."""

    def install_hooks(self):
        self.make_hooks_ref("hooksrc")

    def install(self, ref="hooksrc"):
        r = pwsh_script(HOOKS / "install.ps1", "-Repo", str(self.work), "-Ref", ref, cwd=self.work)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def check(self, ref="hooksrc", script=None):
        return pwsh_script(script or HOOKS / "check-installed.ps1", "-Repo", str(self.work), "-Ref", ref, cwd=self.work)

    def test_current_install_passes(self):
        self.install()
        r = self.check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_main_ahead_of_the_install_fails_naming_the_file_and_install(self):
        self.install()
        self.make_hooks_ref("newer", {"pre_push_guard.py": "# a newer guard\n"})
        r = self.check(ref="newer")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("pre_push_guard.py", r.stdout + r.stderr)
        self.assertIn("install.ps1", r.stdout + r.stderr)

    def test_a_checkout_with_an_older_guard_than_main_still_passes(self):
        """The check runs from a folder holding an OLDER guard; it compares against main, so it passes and never says to install the old one."""
        self.install()
        old = pathlib.Path(self.tmp.name) / "oldbranch"
        old.mkdir()
        shutil.copy(HOOKS / "check-installed.ps1", old / "check-installed.ps1")
        (old / "pre_push_guard.py").write_text("# an older guard\n", encoding="utf-8")
        r = self.check(script=old / "check-installed.ps1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_clone_that_never_installed_fails(self):
        r = self.check()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("install.ps1", r.stdout + r.stderr)

    def test_a_relative_hooks_path_is_not_the_installed_copy(self):
        self.install()
        run(["git", "config", "core.hooksPath", "tools/githooks"], self.work)
        r = self.check()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("install.ps1", r.stdout + r.stderr)

    def test_a_ref_without_the_guard_fails_with_a_fetch_hint(self):
        self.install()
        r = self.check(ref="main")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("tools/githooks", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
