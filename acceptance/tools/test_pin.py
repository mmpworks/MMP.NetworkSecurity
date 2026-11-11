"""Tests for acceptance/tools/pin.py. Run: python -I acceptance/tools/test_pin.py

Each test builds a throwaway git repo with an acceptance/ folder, so no test reads or changes this checkout.
"""
import pathlib
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "tools"))  # the repo's tools/, for the shared temp folder (#400)
from tempdir import TempDir  # noqa: E402

SCRIPT = pathlib.Path(__file__).resolve().parent / "pin.py"


class Pin(unittest.TestCase):
    def setUp(self):
        self.tmp = TempDir()
        self.root = pathlib.Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        self.git("config", "commit.gpgsign", "false")
        self.put("acceptance/CONTRACT.md", "row 1\n")
        self.put("acceptance/groups/a1/One.cs", "class One {}\n")
        self.put("app/main.ts", "x\n")
        self.put("acceptance/settings.json", '{ "pin": true }\n')
        self.commit("base")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, text=True, check=True).stdout

    def put(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)

    def pin(self, *args):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--root", str(self.root), *args], capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def write_and_commit(self):
        code, out = self.pin("--write")
        self.assertEqual(code, 0, out)
        self.commit("pin")

    def test_written_pin_checks_clean(self):
        self.write_and_commit()
        code, out = self.pin("--check")
        self.assertEqual(code, 0, out)

    def test_acceptance_change_without_pin_bump_is_stale(self):
        self.write_and_commit()
        self.put("acceptance/CONTRACT.md", "row 1\nrow 2\n")
        self.commit("new row, no pin")
        code, out = self.pin("--check")
        self.assertEqual(code, 1, out)
        self.assertIn("PIN_STALE", out)
        self.assertIn("pin.py --write", out)

    def test_nested_acceptance_change_is_stale(self):
        self.write_and_commit()
        self.put("acceptance/groups/a1/One.cs", "class One { int x; }\n")
        self.commit("nested change")
        code, out = self.pin("--check")
        self.assertEqual(code, 1, out)
        self.assertIn("PIN_STALE", out)

    def test_bump_after_change_is_clean_again(self):
        self.write_and_commit()
        self.put("acceptance/CONTRACT.md", "row 1\nrow 2\n")
        self.commit("new row")
        self.write_and_commit()
        code, out = self.pin("--check")
        self.assertEqual(code, 0, out)

    def test_change_outside_acceptance_keeps_pin(self):
        self.write_and_commit()
        self.put("app/main.ts", "y\n")
        self.commit("app change")
        code, out = self.pin("--check")
        self.assertEqual(code, 0, out)

    def test_pin_file_itself_is_left_out_of_the_hash(self):
        self.write_and_commit()
        first = (self.root / "acceptance/PIN").read_text(encoding="utf-8")
        code, out = self.pin("--write")
        self.assertEqual(code, 0, out)
        self.assertEqual(first, (self.root / "acceptance/PIN").read_text(encoding="utf-8"))

    def test_id_equals_gits_own_tree_id_when_no_pin_exists(self):
        # With no PIN in the tree, the id must be git's own id for acceptance/. A pipe that turns \n into \r\n (Windows text mode) builds
        # another tree, so Windows and Linux would write different PINs for the same content.
        real = self.git("rev-parse", "HEAD:acceptance").strip()
        code, out = self.pin("--write")
        self.assertEqual(code, 0, out)
        self.assertEqual("acceptance-tree " + real, (self.root / "acceptance/PIN").read_text(encoding="utf-8").strip())

    def test_missing_pin_fails_by_name_when_the_setting_is_on(self):
        code, out = self.pin("--check")
        self.assertEqual(code, 1, out)
        self.assertIn("PIN_MISSING", out)

    def test_deleted_pin_fails_by_name_when_the_setting_is_on(self):
        # The check keys on the committed setting, never on whether PIN exists, so a PR that deletes PIN cannot turn the check off.
        self.write_and_commit()
        (self.root / "acceptance/PIN").unlink()
        self.commit("delete pin")
        code, out = self.pin("--check")
        self.assertEqual(code, 1, out)
        self.assertIn("PIN_MISSING", out)

    def test_setting_off_reports_pin_off(self):
        self.put("acceptance/settings.json", '{ "pin": false }\n')
        self.commit("pin off")
        code, out = self.pin("--check")
        self.assertEqual(code, 0, out)
        self.assertIn("PIN_OFF", out)

    def test_missing_setting_fails_by_name(self):
        (self.root / "acceptance/settings.json").unlink()
        self.commit("no settings")
        code, out = self.pin("--check")
        self.assertEqual(code, 1, out)
        self.assertIn("PIN_SETTING_MISSING", out)

    def test_setting_that_is_not_true_or_false_fails_by_name(self):
        self.put("acceptance/settings.json", '{ "pin": "yes" }\n')
        self.commit("bad setting")
        code, out = self.pin("--check")
        self.assertEqual(code, 1, out)
        self.assertIn("PIN_SETTING_BAD", out)

    def test_old_commit_form_is_refused_by_name(self):
        self.put("acceptance/PIN", self.git("rev-parse", "HEAD").strip() + "\n")
        self.commit("old pin form")
        code, out = self.pin("--check")
        self.assertEqual(code, 1, out)
        self.assertIn("PIN_OLD_FORM", out)

    def test_write_refuses_uncommitted_acceptance_edits(self):
        self.put("acceptance/CONTRACT.md", "row 1\nuncommitted\n")
        code, out = self.pin("--write")
        self.assertEqual(code, 1, out)
        self.assertIn("UNCOMMITTED", out)
        self.assertFalse((self.root / "acceptance/PIN").exists())


if __name__ == "__main__":
    unittest.main(verbosity=1)
