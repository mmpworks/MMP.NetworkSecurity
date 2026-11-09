"""Tests for tools/electron_dist.py. Run: python -I tools/test_electron_dist.py"""
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

SCRIPT = pathlib.Path(__file__).resolve().parent / "electron_dist.py"
VERSION = "33.2.1"
ZIP_NAME = f"electron-v{VERSION}-win32-x64.zip"


class ElectronDist(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        self.app = root / "app"
        self.pkg = self.app / "node_modules" / "electron"
        self.pkg.mkdir(parents=True)
        (self.pkg / "package.json").write_text(json.dumps({"name": "electron", "version": VERSION}), encoding="utf-8")
        self.cache = root / "cache" / "abc123"
        self.cache.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def run_tool(self, *args, env_extra=None):
        env = {"SystemRoot": "C:\\Windows", "PATH": ""}
        env.update(env_extra or {})
        r = subprocess.run([sys.executable, "-I", str(SCRIPT), *args, "--app-dir", str(self.app), "--cache-dir", str(self.cache.parent)],
                           capture_output=True, text=True, env=env)
        return r.returncode, r.stdout + r.stderr

    def make_complete_dist(self):
        dist = self.pkg / "dist"
        (dist / "locales").mkdir(parents=True)
        (dist / "electron.exe").write_bytes(b"MZ")
        (dist / "version").write_text(VERSION, encoding="utf-8")
        (self.pkg / "path.txt").write_text("electron.exe", encoding="utf-8")

    def make_cached_zip(self, checksum=None):
        zip_path = self.cache / ZIP_NAME
        with zipfile.ZipFile(zip_path, "w") as z:
            z.writestr("electron.exe", b"MZ")
            z.writestr("version", VERSION)
            z.writestr("locales/en-US.pak", b"x")
        digest = checksum or hashlib.sha256(zip_path.read_bytes()).hexdigest()
        (self.pkg / "checksums.json").write_text(json.dumps({ZIP_NAME: digest}), encoding="utf-8")

    def test_check_passes_on_a_complete_dist(self):
        self.make_complete_dist()
        code, out = self.run_tool("check")
        self.assertEqual(code, 0, out)

    def test_check_fails_loud_on_a_dist_holding_only_locales(self):
        """The half-install seen on a fresh npm install: extract-zip stopped after locales/."""
        (self.pkg / "dist" / "locales").mkdir(parents=True)
        code, out = self.run_tool("check")
        self.assertEqual(code, 1, out)
        self.assertIn("ELECTRON_DIST_INCOMPLETE", out)
        self.assertIn("electron.exe", out)
        self.assertIn("path.txt", out)
        self.assertIn("electron_dist.py repair", out)

    def test_check_fails_when_the_dist_is_another_version(self):
        self.make_complete_dist()
        (self.pkg / "dist" / "version").write_text("30.0.0", encoding="utf-8")
        code, out = self.run_tool("check")
        self.assertEqual(code, 1, out)
        self.assertIn("ELECTRON_DIST_INCOMPLETE", out)
        self.assertIn("30.0.0", out)

    def test_check_fails_when_the_electron_package_is_absent(self):
        (self.pkg / "package.json").unlink()
        code, out = self.run_tool("check")
        self.assertEqual(code, 1, out)
        self.assertIn("ELECTRON_PACKAGE_MISSING", out)

    def test_check_honours_the_override_dist_path(self):
        other = pathlib.Path(self.tmp.name) / "other-dist"
        other.mkdir()
        (other / "electron.exe").write_bytes(b"MZ")
        code, out = self.run_tool("check", env_extra={"ELECTRON_OVERRIDE_DIST_PATH": str(other)})
        self.assertEqual(code, 0, out)

    def test_repair_extracts_the_cached_zip_after_a_hash_check_and_writes_path_txt(self):
        (self.pkg / "dist" / "locales").mkdir(parents=True)
        self.make_cached_zip()
        code, out = self.run_tool("repair")
        self.assertEqual(code, 0, out)
        self.assertTrue((self.pkg / "dist" / "electron.exe").is_file())
        self.assertEqual((self.pkg / "path.txt").read_text(encoding="utf-8"), "electron.exe")
        self.assertEqual(self.run_tool("check")[0], 0)

    def test_repair_leaves_a_complete_dist_alone(self):
        self.make_complete_dist()
        marker = self.pkg / "dist" / "marker.txt"
        marker.write_text("keep", encoding="utf-8")
        code, out = self.run_tool("repair")
        self.assertEqual(code, 0, out)
        self.assertTrue(marker.is_file(), "a complete dist must not be re-extracted")

    def test_repair_refuses_a_zip_whose_hash_differs_from_checksums_json(self):
        (self.pkg / "dist" / "locales").mkdir(parents=True)
        self.make_cached_zip(checksum="0" * 64)
        code, out = self.run_tool("repair")
        self.assertEqual(code, 1, out)
        self.assertIn("ELECTRON_ZIP_HASH_MISMATCH", out)
        self.assertFalse((self.pkg / "dist" / "electron.exe").exists())

    def test_repair_with_no_cached_zip_fails_loud_and_names_the_installer(self):
        (self.pkg / "dist" / "locales").mkdir(parents=True)
        code, out = self.run_tool("repair")
        self.assertEqual(code, 1, out)
        self.assertIn("ELECTRON_ZIP_NOT_CACHED", out)
        self.assertIn("install.js", out)

    def test_soft_repair_never_fails_an_npm_install(self):
        (self.pkg / "dist" / "locales").mkdir(parents=True)
        code, out = self.run_tool("repair", "--soft")
        self.assertEqual(code, 0, out)
        self.assertIn("ELECTRON_ZIP_NOT_CACHED", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
