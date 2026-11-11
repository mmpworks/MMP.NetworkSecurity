"""One temp folder for the tool tests, whose delete waits out a short outside hold on the folder (#400).

Why: a process outside the test can open or write files in a new temp git repo for a short time. In #400 a run found
`.git/gk/config` with a `gk-last-accessed` line, written about 0.3 s after the test made the repo. A delete in that window fails with
WinError 32 (a sharing violation) or WinError 145 (the directory is not empty, because a file came in during the delete).
One S0 gate run went red in 6 steps that way, with no product fault.

TempDir is tempfile.TemporaryDirectory with one change: cleanup() runs again after a pause when the error is one of RETRY_CODES, up to
ATTEMPTS runs in all. Any other error raises at once, and the last retried error raises too, so a handle the test itself leaks still fails.
"""
import tempfile
import time

SHARING_VIOLATION = 32  # Windows ERROR_SHARING_VIOLATION: another process has the file open
DIR_NOT_EMPTY = 145  # Windows ERROR_DIR_NOT_EMPTY: another process added a file while the delete ran
RETRY_CODES = (SHARING_VIOLATION, DIR_NOT_EMPTY)
ATTEMPTS = 25
PAUSE_S = 0.2  # 25 runs, 24 pauses: a hold longer than about 5 s still fails the test


def retry_while_held(action, attempts=ATTEMPTS, pause=PAUSE_S, sleep=time.sleep):
    """Run action and return its result. On an error in RETRY_CODES, sleep for pause and run it again, up to attempts runs in all."""
    for attempt in range(1, attempts + 1):
        try:
            return action()
        except OSError as error:
            if getattr(error, "winerror", None) not in RETRY_CODES or attempt == attempts:
                raise
            sleep(pause)


class TempDir(tempfile.TemporaryDirectory):
    """tempfile.TemporaryDirectory whose cleanup() waits out a short outside hold. Use it in setUp/tearDown or in a with block."""

    def __init__(self, *args, attempts=ATTEMPTS, pause=PAUSE_S, sleep=time.sleep, **kwargs):
        super().__init__(*args, **kwargs)
        self._retry = dict(attempts=attempts, pause=pause, sleep=sleep)

    def cleanup(self):
        # A second run of TemporaryDirectory.cleanup() deletes again while the folder exists, so a retry finishes a partial delete.
        retry_while_held(super().cleanup, **self._retry)
