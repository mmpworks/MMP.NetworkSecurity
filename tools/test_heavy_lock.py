"""Tests for tools/heavy_lock.py, the machine-wide lock for heavy runs (full gate, full app suite, acceptance, load loops).
The lock is an OS file lock held by the `run` process, so a crash releases it and no stale-lock logic exists to race.
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

TOOL = pathlib.Path(os.environ.get("HEAVY_LOCK_TOOL") or pathlib.Path(__file__).resolve().parent / "heavy_lock.py")   # the override lets a test run against an older copy
spec = importlib.util.spec_from_file_location("heavy_lock", TOOL)
heavy_lock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(heavy_lock)

PY = [sys.executable, "-I", "-c"]
SLEEP_60 = PY + ["import time; time.sleep(60)"]


class HeavyLock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name) / "locks"          # does not exist yet: the tool makes it
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            if p.poll() is None:
                subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True)
        self.tmp.cleanup()

    def env(self, **extra):
        e = dict(os.environ)
        e.pop("NETSEC_HEAVY_LOCK_HELD", None)
        e.pop("NETSEC_LOCK_DIR", None)
        e.update(extra)
        return e

    def tool(self, *args, env=None, timeout=60):
        args = list(args)
        at = args.index("--") if "--" in args else len(args)        # --lock-dir goes before the command, not after it
        args[at:at] = ["--lock-dir", str(self.dir)]
        return subprocess.run([sys.executable, "-I", str(TOOL), *args], capture_output=True, text=True, env=env or self.env(), timeout=timeout)

    def start_run(self, label, *command, wait=None, env=None):
        args = [sys.executable, "-I", str(TOOL), "run", "--label", label, "--lock-dir", str(self.dir)]
        if wait is not None:
            args += ["--wait-minutes", str(wait)]
        p = subprocess.Popen(args + ["--", *command], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env or self.env())
        self.procs.append(p)
        return p

    def wait_until_held(self, seconds=20):
        end = time.time() + seconds
        while time.time() < end:
            if self.tool("status").returncode == 2:
                return
            time.sleep(0.3)
        self.fail("the lock never became held")

    def test_run_takes_the_lock_while_the_command_runs_and_frees_it_after(self):
        p = self.start_run("long job", *PY, "import time; time.sleep(4)")
        self.wait_until_held()
        status = self.tool("status")
        self.assertEqual(status.returncode, 2, status.stdout)
        self.assertIn("long job", status.stdout)
        p.communicate(timeout=60)
        self.assertEqual(self.tool("status").returncode, 0)

    def test_run_passes_the_exit_code_through_and_releases(self):
        r = self.tool("run", "--label", "child", "--", *PY, "import sys; sys.exit(7)")
        self.assertEqual(r.returncode, 7, r.stdout + r.stderr)
        self.assertEqual(self.tool("status").returncode, 0)

    def test_the_command_is_told_which_run_holds_the_lock(self):
        r = self.tool("run", "--label", "child", "--", *PY, "import os; print('held-by=' + os.environ.get('NETSEC_HEAVY_LOCK_HELD', ''))")
        self.assertRegex(r.stdout, r"held-by=\d+")

    def test_a_second_run_waits_names_the_holder_at_once_and_times_out_with_a_code(self):
        self.start_run("gate AppProof", *SLEEP_60)
        self.wait_until_held()
        t0 = time.time()
        r = self.tool("run", "--label", "second", "--wait-minutes", "0.05", "--", *PY, "print('must not run')")
        self.assertEqual(r.returncode, 75, r.stdout + r.stderr)
        self.assertIn("HEAVY_LOCK waiting on 'gate AppProof'", r.stdout)
        self.assertIn("LOCK_TIMEOUT", r.stdout)
        self.assertNotIn("must not run", r.stdout)
        self.assertLess(time.time() - t0, 30)
        self.assertEqual(self.tool("status").returncode, 2, "the waiter did not disturb the holder")

    def test_a_waiter_gets_the_lock_when_the_holder_ends(self):
        self.start_run("first", *PY, "import time; time.sleep(4)")
        self.wait_until_held()
        waiter = self.start_run("second", *PY, "print('second ran')", wait=2)
        out, _ = waiter.communicate(timeout=90)
        self.assertEqual(waiter.returncode, 0, out)
        self.assertIn("HEAVY_LOCK waiting on 'first'", out)
        self.assertIn("second ran", out)

    def test_a_killed_runner_frees_the_lock_at_once_and_the_next_run_takes_it(self):
        p = self.start_run("doomed", *SLEEP_60)
        self.wait_until_held()
        subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"], capture_output=True)    # a crash: nothing runs the release
        p.wait(timeout=30)
        t0 = time.time()
        r = self.tool("run", "--label", "after the crash", "--wait-minutes", "0.5", "--", *PY, "print('took it')")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("took it", r.stdout)
        self.assertNotIn("waiting", r.stdout)
        self.assertLess(time.time() - t0, 20)

    def test_runs_never_overlap_when_many_start_at_once(self):
        """The mutual exclusion itself: 6 runners start together; each marks in/out around a short sleep in a shared file; the intervals must not overlap."""
        marks = pathlib.Path(self.tmp.name) / "marks.txt"
        script = ("import os, sys, time\n"
                  "with open(sys.argv[1], 'a') as f: f.write('in %d %f\\n' % (os.getpid(), time.time()))\n"
                  "time.sleep(0.6)\n"
                  "with open(sys.argv[1], 'a') as f: f.write('out %d %f\\n' % (os.getpid(), time.time()))\n")
        runners = [self.start_run(f"runner {i}", sys.executable, "-I", "-c", script, str(marks), wait=3) for i in range(6)]
        for p in runners:
            p.communicate(timeout=120)
            self.assertEqual(p.returncode, 0)
        events = [line.split() for line in marks.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(events), 12)
        events.sort(key=lambda e: float(e[2]))
        inside = 0
        for kind, _pid, _t in events:
            inside += 1 if kind == "in" else -1
            self.assertIn(inside, (0, 1), f"two runs held the lock at once: {events}")

    def test_a_run_inside_the_holder_proceeds_without_waiting(self):
        holder = self.start_run("outer gate", *PY, "import os, subprocess, sys, time; "
                                "r = subprocess.run([sys.executable, '-I', %r, 'run', '--label', 'inner suite', '--lock-dir', %r, '--wait-minutes', '0.05', '--', "
                                "sys.executable, '-I', '-c', 'print(\"inner ran\")']); print('inner exit', r.returncode)" % (str(TOOL), str(self.dir)))
        out, _ = holder.communicate(timeout=90)
        self.assertIn("inner ran", out)
        self.assertIn("inner exit 0", out)
        self.assertIn("already held by an ancestor", out)

    def test_a_false_claim_of_being_inside_the_holder_still_waits(self):
        self.start_run("real holder", *SLEEP_60)
        self.wait_until_held()
        r = self.tool("run", "--label", "liar", "--wait-minutes", "0.05", "--", *PY, "print('must not run')", env=self.env(NETSEC_HEAVY_LOCK_HELD="99999999"))
        self.assertEqual(r.returncode, 75, r.stdout + r.stderr)
        self.assertNotIn("must not run", r.stdout)

    def test_a_holder_with_no_info_file_still_blocks_and_the_wait_message_says_so(self):
        """The lock is the OS lock, not the info file: with the info missing a second run still waits."""
        p = self.start_run("quiet holder", *SLEEP_60)
        self.wait_until_held()
        (self.dir / "heavy-run.info").write_text("", encoding="utf-8")        # the details vanish; the lock stays
        r = self.tool("run", "--label", "second", "--wait-minutes", "0.05", "--", *PY, "print('must not run')")
        self.assertEqual(r.returncode, 75, r.stdout + r.stderr)
        self.assertIn("details are not written yet", r.stdout)
        self.assertIsNone(p.poll())

    # The two races Jared found in the pid-file version, as tests that hold for any correct lock.
    def test_two_waiters_behind_a_crashed_holder_never_overlap(self):
        """Race 1 (stale replace): a holder crashed and left its files; two runs start at once. Exactly one may run at a time."""
        crashed = self.start_run("crashed holder", *SLEEP_60)
        self.wait_until_held()
        subprocess.run(["taskkill", "/PID", str(crashed.pid), "/T", "/F"], capture_output=True)
        crashed.wait(timeout=30)
        marks = pathlib.Path(self.tmp.name) / "marks2.txt"
        script = ("import os, sys, time\n"
                  "with open(sys.argv[1], 'a') as f: f.write('in %d %f\\n' % (os.getpid(), time.time()))\n"
                  "time.sleep(1.5)\n"
                  "with open(sys.argv[1], 'a') as f: f.write('out %d %f\\n' % (os.getpid(), time.time()))\n")
        pair = [self.start_run(f"waiter {i}", sys.executable, "-I", "-c", script, str(marks), wait=3) for i in range(2)]
        for p in pair:
            p.communicate(timeout=120)
            self.assertEqual(p.returncode, 0)
        events = sorted((line.split() for line in marks.read_text(encoding="utf-8").splitlines()), key=lambda e: float(e[2]))
        self.assertEqual([e[0] for e in events], ["in", "out", "in", "out"], f"the two waiters overlapped: {events}")

    def test_a_reader_in_the_gap_between_creating_the_lock_and_writing_who_holds_it_still_waits(self):
        """Race 2 (empty-file window): the holder's details are missing or half written. A waiter that reads them must wait, not take the lock."""
        self.start_run("holder", *SLEEP_60)
        self.wait_until_held()
        for partial in ("", '{"pid": 12', "not json at all", "[]"):
            (self.dir / "heavy-run.info").write_text(partial, encoding="utf-8")
            r = self.tool("run", "--label", "reader", "--wait-minutes", "0.03", "--", *PY, "print('must not run')")
            self.assertEqual(r.returncode, 75, f"info={partial!r}: {r.stdout + r.stderr}")
            self.assertNotIn("must not run", r.stdout)

    def alive(self, pid):
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True, text=True).stdout
        return str(pid) in out

    def test_a_dead_runner_leaves_no_heavy_work_behind(self):
        """Jared's finding: the lock lives on the runner. If the runner dies (TaskStop, a crash) and its child lives on, the lock frees while heavy work still runs.
        The child must die with the runner, so a second run never starts on top of it."""
        pidfile = pathlib.Path(self.tmp.name) / "child.pid"
        child = f"import os, time; open(r'{pidfile}', 'w').write(str(os.getpid())); time.sleep(300)"
        runner = self.start_run("orphan check", *PY, child)
        self.wait_until_held()
        for _ in range(100):
            if pidfile.exists() and pidfile.read_text(encoding="utf-8"):
                break
            time.sleep(0.1)
        child_pid = int(pidfile.read_text(encoding="utf-8"))
        try:
            subprocess.run(["taskkill", "/PID", str(runner.pid), "/F"], capture_output=True)          # the runner only: no /T, like a killed task
            runner.wait(timeout=30)
            deadline = time.time() + 15                                    # a deadline, not a count: each tasklist call takes about a second
            while time.time() < deadline and self.alive(child_pid):
                time.sleep(0.2)
            self.assertFalse(self.alive(child_pid), "the heavy command is still running after its runner died")
        finally:
            subprocess.run(["taskkill", "/PID", str(child_pid), "/F"], capture_output=True)

    # The gem probe-what-you-bind: the acquisition is the probe, and an unexpected lock error is never read as "free".
    def test_a_lock_folder_that_cannot_be_made_fails_closed_with_a_named_code(self):
        blocker = pathlib.Path(self.tmp.name) / "a-file-not-a-folder"
        blocker.write_text("x", encoding="utf-8")
        self.dir = blocker / "locks"
        r = self.tool("run", "--label", "x", "--wait-minutes", "0.05", "--", *PY, "print('must not run')")
        self.assertEqual(r.returncode, 76, r.stdout + r.stderr)
        self.assertIn("LOCK_ERROR", r.stdout)
        self.assertNotIn("must not run", r.stdout)

    def test_status_reports_an_error_as_an_error_not_as_free(self):
        blocker = pathlib.Path(self.tmp.name) / "a-file-not-a-folder"
        blocker.write_text("x", encoding="utf-8")
        self.dir = blocker / "locks"
        r = self.tool("status")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("LOCK_ERROR", r.stdout)
        self.assertNotIn("heavy-run lock: free", r.stdout)

    def test_a_lock_file_that_cannot_be_opened_fails_closed(self):
        self.dir.mkdir(parents=True)
        lock = self.dir / "heavy-run.lock"
        lock.write_bytes(b"\0")
        os.chmod(lock, 0o444)                                           # read-only: opening it for locking is refused
        try:
            r = self.tool("run", "--label", "x", "--wait-minutes", "0.05", "--", *PY, "print('must not run')")
        finally:
            os.chmod(lock, 0o666)
        self.assertEqual(r.returncode, 76, r.stdout + r.stderr)
        self.assertIn("LOCK_ERROR", r.stdout)
        self.assertNotIn("must not run", r.stdout)

    def test_a_planted_info_file_for_a_dead_process_does_not_block_a_free_lock(self):
        self.dir.mkdir(parents=True)
        (self.dir / "heavy-run.info").write_text(json.dumps({"pid": 99999999, "label": "ghost", "started": "2026-11-08T01:00:00"}), encoding="utf-8")
        r = self.tool("run", "--label", "real", "--wait-minutes", "0.1", "--", *PY, "print('took it')")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("took it", r.stdout)

    def test_status_says_free_when_nobody_holds_it_and_makes_the_folder(self):
        r = self.tool("status")
        self.assertEqual(r.returncode, 0)
        self.assertIn("free", r.stdout)
        self.assertTrue(self.dir.exists())

    def test_the_lock_folder_can_come_from_the_environment(self):
        other = pathlib.Path(self.tmp.name) / "from-env"
        r = subprocess.run([sys.executable, "-I", str(TOOL), "run", "--label", "env", "--", *PY, "pass"], capture_output=True, text=True,
                           env=self.env(NETSEC_LOCK_DIR=str(other)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(other.exists())

    def test_process_start_is_stable_for_a_live_process_and_none_for_a_dead_one(self):
        p = subprocess.Popen(SLEEP_60)
        self.procs.append(p)
        self.assertEqual(heavy_lock.process_start(p.pid), heavy_lock.process_start(p.pid))
        self.assertIsNotNone(heavy_lock.process_start(p.pid))
        q = subprocess.Popen(PY + ["pass"])
        q.wait()
        self.assertIsNone(heavy_lock.process_start(q.pid))

    @unittest.skipUnless(os.name == "nt", "pid 4 is the Windows System process")
    def test_a_live_process_that_cannot_be_opened_counts_as_alive(self):
        self.assertIsNotNone(heavy_lock.process_start(4))


if __name__ == "__main__":
    unittest.main(verbosity=2)
