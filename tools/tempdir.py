"""One temp folder for the tool tests (#400). RED STUB: cleanup() has no retry yet."""
import tempfile
import time

SHARING_VIOLATION = 32  # Windows ERROR_SHARING_VIOLATION
ATTEMPTS = 25
PAUSE_S = 0.2


def retry_sharing(action, attempts=ATTEMPTS, pause=PAUSE_S, sleep=time.sleep):
    """RED STUB: runs action once."""
    return action()


class TempDir(tempfile.TemporaryDirectory):
    """RED STUB: tempfile.TemporaryDirectory with the final signature and no retry."""

    def __init__(self, *args, attempts=ATTEMPTS, pause=PAUSE_S, sleep=time.sleep, **kwargs):
        super().__init__(*args, **kwargs)
        self._retry = dict(attempts=attempts, pause=pause, sleep=sleep)

    def cleanup(self):
        retry_sharing(super().cleanup, **self._retry)
