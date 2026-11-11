"""One temp folder for the tool tests, whose delete waits out a short sharing lock (#400).

Why: a process outside the test (cause unverified in #400) can hold a handle in a new temp folder for a short time. A delete in that window
fails with WinError 32, a sharing violation. One S0 gate run went red in 6 steps that way, with no product fault.

TempDir is tempfile.TemporaryDirectory with one change: cleanup() runs again after a pause when the error is a sharing violation, up to
ATTEMPTS runs in all. Any other error raises at once, and the last sharing violation raises too, so a handle the test itself leaks still fails.
"""
import tempfile
import time

SHARING_VIOLATION = 32  # Windows ERROR_SHARING_VIOLATION
ATTEMPTS = 25
PAUSE_S = 0.2  # 25 runs, 24 pauses: a lock longer than about 5 s still fails the test


def retry_sharing(action, attempts=ATTEMPTS, pause=PAUSE_S, sleep=time.sleep):
    """Run action and return its result. On a sharing violation, sleep for pause and run it again, up to attempts runs in all."""
    for attempt in range(1, attempts + 1):
        try:
            return action()
        except OSError as error:
            if getattr(error, "winerror", None) != SHARING_VIOLATION or attempt == attempts:
                raise
            sleep(pause)


class TempDir(tempfile.TemporaryDirectory):
    """tempfile.TemporaryDirectory whose cleanup() waits out a short sharing lock. Use it in setUp/tearDown or in a with block."""

    def __init__(self, *args, attempts=ATTEMPTS, pause=PAUSE_S, sleep=time.sleep, **kwargs):
        super().__init__(*args, **kwargs)
        self._retry = dict(attempts=attempts, pause=pause, sleep=sleep)

    def cleanup(self):
        # A second run of TemporaryDirectory.cleanup() deletes again while the folder exists, so a retry finishes a partial delete.
        retry_sharing(super().cleanup, **self._retry)
