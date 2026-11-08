"""The gate takes the heavy-run lock: with another holder it waits (and never starts a step); with a free lock it runs under the lock.
Run: python -I tools/test_gate_lock.py
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent
GATE = TOOLS / "gate.ps1"
LOCK = TOOLS / "heavy_lock.py"


class GateLock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.holder = None

    def tearDown(self):
        if self.holder and self.holder.poll() is None:
            subprocess.run(["taskkill", "/PID", str(self.holder.pid), "/T", "/F"], capture_output=True)
        self.tmp.cleanup()

    def env(self, **extra):
        e = dict(os.environ, NETSEC_LOCK_DIR=str(self.dir))
        e.pop("NETSEC_HEAVY_LOCK_HELD", None)
        e.update(extra)
        return e

    def hold(self, label):
        self.holder = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(300)"])
        r = subprocess.run([sys.executable, "-I", str(LOCK), "acquire", "--label", label, "--pid", str(self.holder.pid)], env=self.env(), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_gate_waits_behind_another_holder_and_starts_no_step(self):
        self.hold("richard hang loop")
        r = subprocess.run(["pwsh", "-NoProfile", "-File", str(GATE), "-Slice", "LockTest", "-SkipApp"], capture_output=True, text=True,
                           env=self.env(NETSEC_LOCK_WAIT_MINUTES="0.05"), timeout=120)
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 75, out)
        self.assertIn("HEAVY_LOCK waiting on 'richard hang loop'", out)
        self.assertIn("LOCK_TIMEOUT", out)
        self.assertNotIn("== layer_check", out, "no gate step may start while another run holds the lock")

    def test_the_gate_script_passes_its_own_parameters_to_the_locked_run(self):
        text = GATE.read_text(encoding="utf-8")
        self.assertIn("heavy_lock.py", text)
        self.assertIn("$PSBoundParameters", text)
        self.assertIn("NETSEC_HEAVY_LOCK_HELD", text)
        self.assertIn('--label "gate $Slice"', text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
