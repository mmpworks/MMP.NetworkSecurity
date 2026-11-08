"""Tests for tools/heavy_lock.py, the machine-wide lock for heavy runs (full gate, full app suite, acceptance, load loops).
Run: python -I tools/test_heavy_lock.py
"""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

TOOL = pathlib.Path(__file__).resolve().parent / "heavy_lock.py"
spec = importlib.util.spec_from_file_location("heavy_lock", TOOL)
heavy_lock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(heavy_lock)

SLEEP = [sys.executable, "-I", "-c", "import time; time.sleep(120)"]


class HeavyLock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name) / "locks"          # does not exist yet: the tool makes it
        self.lock = self.dir / "heavy-run.lock"
        self.helpers = []

    def tearDown(self):
        for p in self.helpers:
            if p.poll() is None:
                subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True)
        self.tmp.cleanup()

    def tool(self, *args, env=None, timeout=60):
        e = dict(os.environ)
        e.pop("NETSEC_HEAVY_LOCK_HELD", None)
        e.pop("NETSEC_LOCK_DIR", None)
        e.update(env or {})
        return subprocess.run([sys.executable, "-I", str(TOOL), *args, "--lock-dir", str(self.dir)], capture_output=True, text=True, env=e, timeout=timeout)

    def live_process(self):
        p = subprocess.Popen(SLEEP)
        self.helpers.append(p)
        return p

    def dead_pid(self):
        p = subprocess.Popen([sys.executable, "-I", "-c", "pass"])
        p.wait()
        return p.pid

    def holder(self):
        return json.loads(self.lock.read_text(encoding="utf-8"))

    def test_acquire_on_a_free_lock_takes_it_and_creates_the_folder(self):
        h = self.live_process()
        r = self.tool("acquire", "--label", "first", "--pid", str(h.pid))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        data = self.holder()
        self.assertEqual((data["pid"], data["label"]), (h.pid, "first"))
        self.assertIn("started", data)

    def test_a_second_run_waits_names_the_holder_at_once_and_times_out_with_a_code(self):
        h = self.live_process()
        self.tool("acquire", "--label", "gate AppProof", "--pid", str(h.pid))
        t0 = time.time()
        r = self.tool("acquire", "--label", "second", "--pid", str(os.getpid()), "--wait-minutes", "0.05")
        self.assertEqual(r.returncode, 75, r.stdout + r.stderr)
        self.assertIn("HEAVY_LOCK waiting on 'gate AppProof'", r.stdout)
        self.assertIn(f"pid {h.pid}", r.stdout)
        self.assertIn("LOCK_TIMEOUT", r.stdout)
        self.assertLess(time.time() - t0, 30)
        self.assertEqual(self.holder()["label"], "gate AppProof", "the waiter did not take or damage the lock")

    def test_a_waiter_gets_the_lock_when_the_holder_releases(self):
        h = self.live_process()
        self.tool("acquire", "--label", "first", "--pid", str(h.pid))
        me = self.live_process()
        waiter = subprocess.Popen([sys.executable, "-I", str(TOOL), "acquire", "--label", "second", "--pid", str(me.pid), "--wait-minutes", "2",
                                   "--lock-dir", str(self.dir)], stdout=subprocess.PIPE, text=True)
        self.helpers.append(waiter)
        time.sleep(2)
        self.assertIsNone(waiter.poll(), "the waiter must still be waiting")
        self.assertEqual(self.tool("release", "--pid", str(h.pid)).returncode, 0)
        out, _ = waiter.communicate(timeout=60)
        self.assertEqual(waiter.returncode, 0, out)
        self.assertEqual(self.holder()["label"], "second")

    def test_a_dead_holder_is_stale_and_replaced(self):
        self.dir.mkdir(parents=True)
        self.lock.write_text(json.dumps({"pid": self.dead_pid(), "start": "x", "label": "crashed gate", "started": "2026-11-08T01:00:00"}), encoding="utf-8")
        me = self.live_process()
        r = self.tool("acquire", "--label", "next", "--pid", str(me.pid), "--wait-minutes", "0.1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("stale", r.stdout.lower())
        self.assertEqual(self.holder()["label"], "next")

    def test_a_reused_pid_with_another_start_time_is_stale(self):
        h = self.live_process()
        self.dir.mkdir(parents=True)
        self.lock.write_text(json.dumps({"pid": h.pid, "start": "not this process's start time", "label": "old holder",
                                         "started": "2026-11-08T01:00:00"}), encoding="utf-8")
        me = self.live_process()
        r = self.tool("acquire", "--label", "next", "--pid", str(me.pid), "--wait-minutes", "0.1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("stale", r.stdout.lower())

    def test_release_by_a_process_that_does_not_hold_the_lock_is_refused(self):
        h = self.live_process()
        self.tool("acquire", "--label", "first", "--pid", str(h.pid))
        other = self.live_process()
        r = self.tool("release", "--pid", str(other.pid))
        self.assertEqual(r.returncode, 1)
        self.assertIn("LOCK_NOT_HELD", r.stdout)
        self.assertEqual(self.holder()["label"], "first")

    def test_release_by_the_holder_frees_the_lock(self):
        h = self.live_process()
        self.tool("acquire", "--label", "first", "--pid", str(h.pid))
        self.assertEqual(self.tool("release", "--pid", str(h.pid)).returncode, 0)
        self.assertFalse(self.lock.exists())

    def test_run_passes_the_exit_code_through_and_releases(self):
        r = self.tool("run", "--label", "child", "--", sys.executable, "-I", "-c", "import sys; sys.exit(7)")
        self.assertEqual(r.returncode, 7, r.stdout + r.stderr)
        self.assertFalse(self.lock.exists(), "the lock is released when the command ends")

    def test_run_holds_the_lock_while_the_command_runs_and_tells_it_so(self):
        p = subprocess.Popen([sys.executable, "-I", str(TOOL), "run", "--label", "long job", "--lock-dir", str(self.dir), "--", sys.executable, "-I", "-c",
                              "import os, time; print('held-by=' + os.environ.get('NETSEC_HEAVY_LOCK_HELD', ''), flush=True); time.sleep(4)"],
                             stdout=subprocess.PIPE, text=True)
        self.helpers.append(p)
        time.sleep(2)
        status = self.tool("status")
        self.assertEqual(status.returncode, 2, status.stdout)
        self.assertIn("long job", status.stdout)
        out, _ = p.communicate(timeout=60)
        self.assertIn(f"held-by={self.holder_pid_from(out)}", out)

    @staticmethod
    def holder_pid_from(out):
        return out.split("held-by=")[1].split()[0]

    def test_a_killed_runner_leaves_a_stale_lock_that_the_next_run_takes(self):
        p = subprocess.Popen([sys.executable, "-I", str(TOOL), "run", "--label", "doomed", "--lock-dir", str(self.dir), "--", *SLEEP], stdout=subprocess.PIPE)
        self.helpers.append(p)
        time.sleep(2)
        self.assertEqual(self.holder()["label"], "doomed")
        subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True)    # a crash: nothing runs the release
        p.wait(timeout=30)
        me = self.live_process()
        r = self.tool("acquire", "--label", "after the crash", "--pid", str(me.pid), "--wait-minutes", "0.1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.holder()["label"], "after the crash")

    def test_a_run_started_inside_the_holder_proceeds_without_waiting_or_taking_the_lock(self):
        h = self.live_process()
        self.tool("acquire", "--label", "outer gate", "--pid", str(h.pid))
        t0 = time.time()
        r = self.tool("run", "--label", "inner suite", "--", sys.executable, "-I", "-c", "print('inner ran')", env={"NETSEC_HEAVY_LOCK_HELD": str(h.pid)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("inner ran", r.stdout)
        self.assertLess(time.time() - t0, 20)
        self.assertEqual(self.holder()["label"], "outer gate", "the inner run left the outer holder in place")

    def test_a_claim_of_being_inside_a_holder_that_is_not_the_holder_does_not_skip_the_wait(self):
        h = self.live_process()
        self.tool("acquire", "--label", "real holder", "--pid", str(h.pid))
        r = self.tool("acquire", "--label", "liar", "--pid", str(os.getpid()), "--wait-minutes", "0.05", env={"NETSEC_HEAVY_LOCK_HELD": "99999999"})
        self.assertEqual(r.returncode, 75, r.stdout + r.stderr)

    def test_status_says_free_when_nobody_holds_it(self):
        r = self.tool("status")
        self.assertEqual(r.returncode, 0)
        self.assertIn("free", r.stdout)

    def test_the_lock_folder_can_come_from_the_environment(self):
        other = pathlib.Path(self.tmp.name) / "from-env"
        e = dict(os.environ, NETSEC_LOCK_DIR=str(other))
        e.pop("NETSEC_HEAVY_LOCK_HELD", None)
        r = subprocess.run([sys.executable, "-I", str(TOOL), "run", "--label", "env", "--", sys.executable, "-I", "-c", "pass"], capture_output=True, text=True, env=e)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(other.exists())

    def test_process_start_is_stable_for_a_live_process_and_none_for_a_dead_one(self):
        h = self.live_process()
        self.assertEqual(heavy_lock.process_start(h.pid), heavy_lock.process_start(h.pid))
        self.assertIsNotNone(heavy_lock.process_start(h.pid))
        self.assertIsNone(heavy_lock.process_start(self.dead_pid()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
