"""Tests for tools/tempdir.py, the shared temp folder of the tool tests (#400). Run: python -I tools/test_tempdir.py

A file held open inside the folder makes the fault. Python opens a file with no delete share, so a delete of the folder fails with
WinError 32 (a sharing violation) until that handle closes. That is the error a short outside lock gave in #400.
"""
import os
import pathlib
import sys
import threading
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # tools/, where tempdir.py is (python -I leaves it off sys.path)
from tempdir import DIR_NOT_EMPTY, SHARING_VIOLATION, TempDir, retry_while_held  # noqa: E402

WINDOWS = os.name == "nt"


def hold(folder):
    """Open a file inside folder and keep it open, so a delete of folder fails with WinError 32 until the caller closes it."""
    return open(pathlib.Path(folder) / "held.bin", "wb")


class Sleeps:
    """A sleep that records each pause and waits for none, so a test can count the retries."""

    def __init__(self):
        self.pauses = []

    def __call__(self, seconds):
        self.pauses.append(seconds)


@unittest.skipUnless(WINDOWS, "the sharing violation is a Windows error")
class HeldOpen(unittest.TestCase):
    def test_a_lock_that_ends_inside_the_retry_window_is_waited_out(self):
        tmp = TempDir()
        held = hold(tmp.name)
        threading.Timer(0.5, held.close).start()
        tmp.cleanup()
        self.assertFalse(os.path.exists(tmp.name))

    def test_the_with_form_waits_out_the_lock_too(self):
        with TempDir() as name:
            held = hold(name)
            threading.Timer(0.5, held.close).start()
        self.assertFalse(os.path.exists(name))

    def test_a_lock_that_outlasts_the_attempts_raises_the_sharing_violation(self):
        sleeps = Sleeps()
        tmp = TempDir(attempts=4, pause=0.05, sleep=sleeps)
        held = hold(tmp.name)
        try:
            with self.assertRaises(PermissionError) as caught:
                tmp.cleanup()
            self.assertEqual(SHARING_VIOLATION, caught.exception.winerror)
            self.assertEqual([0.05, 0.05, 0.05], sleeps.pauses, "4 attempts in all, so 3 pauses between them")
        finally:
            held.close()
            tmp.cleanup()
        self.assertFalse(os.path.exists(tmp.name))


class Rules(unittest.TestCase):
    def test_a_free_folder_goes_on_the_first_try(self):
        sleeps = Sleeps()
        tmp = TempDir(sleep=sleeps)
        (pathlib.Path(tmp.name) / "a.txt").write_text("a")
        tmp.cleanup()
        self.assertFalse(os.path.exists(tmp.name))
        self.assertEqual([], sleeps.pauses)

    def test_an_error_other_than_a_sharing_violation_raises_at_once(self):
        sleeps = Sleeps()
        calls = []

        def fails():
            calls.append(1)
            raise FileNotFoundError("no such folder")

        with self.assertRaises(FileNotFoundError):
            retry_while_held(fails, attempts=5, pause=0.05, sleep=sleeps)
        self.assertEqual(1, len(calls))
        self.assertEqual([], sleeps.pauses)

    def test_each_retried_error_that_clears_returns_the_result(self):
        # 32: a file is open in another process. 145: another process added a file while the delete ran (the .git/gk case in #400).
        for code, kind in ((SHARING_VIOLATION, PermissionError), (DIR_NOT_EMPTY, OSError)):
            with self.subTest(winerror=code):
                sleeps = Sleeps()
                calls = []

                def clears_on_third():
                    calls.append(1)
                    if len(calls) < 3:
                        error = kind("held")
                        error.winerror = code
                        raise error
                    return "done"

                self.assertEqual("done", retry_while_held(clears_on_third, attempts=5, pause=0.05, sleep=sleeps))
                self.assertEqual(3, len(calls))
                self.assertEqual([0.05, 0.05], sleeps.pauses)


if __name__ == "__main__":
    unittest.main(verbosity=2)
