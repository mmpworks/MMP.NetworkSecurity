"""Tests for tools/transport_name_lint.py. Run: python -I tools/test_transport_name_lint.py"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "transport_name_lint.py"


class TransportNameLint(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "app" / "src" / "views").mkdir(parents=True)
        self.put("app/src/types.ts", "export type Transport = 'glass' | 'os'\n")

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, rel, text):
        (self.root / rel).write_text(text, encoding="utf-8")

    def run_check(self):
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), "--root", str(self.root)], capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def test_a_clean_tree_passes(self):
        self.put("app/src/views/Run.vue", "<script setup>const t = 'os'</script>\n")
        code, out = self.run_check()
        self.assertEqual(code, 0, out)

    def test_a_quoted_real_fails_and_names_file_and_line(self):
        self.put("app/src/views/Run.vue", "line one\nconst t = \"real\"\n")
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("TRANSPORT_OLD_NAME: app/src/views/Run.vue:2:", out)

    def test_is_real_fails(self):
        self.put("app/src/store.ts", "if (isReal) {}\n")
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("app/src/store.ts:1:", out)

    def test_the_word_real_outside_quotes_passes(self):
        self.put("app/src/store.ts", "// a real server, realtime, isRealm\n")
        code, out = self.run_check()
        self.assertEqual(code, 0, out)

    def test_types_without_os_fails_by_name(self):
        self.put("app/src/types.ts", "export type Transport = 'glass'\n")
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("TRANSPORT_OS_NOT_NAMED", out)

    def test_a_tree_with_no_app_fails_by_name(self):
        self.tmp.cleanup()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        code, out = self.run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("TRANSPORT_NAME_NO_APP", out)


if __name__ == "__main__":
    unittest.main()
