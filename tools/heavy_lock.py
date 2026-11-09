#!/usr/bin/env python3
"""A machine-wide lock for heavy runs: the full gate, the full app suite, acceptance runs, and load loops.

Why: ports are partitioned per run (NETSEC_PORT_BASE) but CPU is not. Heavy runs stacked on one machine pushed CPU to 100% and made product timing
tests fail in a different place each time (a test-host hang, a CE-READY timeout, a Host with no ready line in 60 s). One heavy run at a time removes
that noise. Small targeted runs stay unlocked. A load burner or a hang loop counts as a heavy run and takes the lock like a gate does.

  python -I tools/heavy_lock.py run --label "gate AppProof" [--wait-minutes M] -- <command> [args]   take the lock, run the command, release
  python -I tools/heavy_lock.py status                                                               exit 0 free, 2 held (names the holder)

The lock is an OS file lock on <lock dir>\\heavy-run.lock, held by the `run` process for as long as it lives (msvcrt.locking on Windows, fcntl.flock
elsewhere). The OS drops it when that process ends, including a crash or a kill, so nothing is ever stale and nothing needs cleanup: there is no pid
check, no pid reuse and no replace race. A second file, heavy-run.info, holds the holder's pid, label and start time for the waiting message only;
it never decides who holds the lock. The lock folder is %LOCALAPPDATA%\\mmp-netsec\\locks (NETSEC_LOCK_DIR or --lock-dir override).
A waiter prints "HEAVY_LOCK waiting on '<label>' (pid N, started HH:MM, M min ago)" at once and every 30 seconds.
`run` sets NETSEC_HEAVY_LOCK_HELD=<holder pid> for its command; a run started inside a holder (the gate's own app suite) proceeds without waiting,
but only when that pid is the live holder named in the info file and the lock is really held.
Exit codes: the command's own code from `run`; 75 LOCK_TIMEOUT; 76 LOCK_ERROR (an unexpected lock failure: the run stops, fail closed, and `status`
exits 1 with the same text); 77 COMMAND_NOT_FOUND (checked before the lock is touched); 2 from `status` when held.
Waiters run in arrival order: each writes a ticket file under <lock dir>\tickets, and only the oldest live ticket may try the OS lock. The OS lock still
decides who holds; tickets of dead processes and junk files are skipped.
The command is resolved with shutil.which first, so `npm` finds npm.cmd on Windows.
"""
import argparse
import ctypes
import errno
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
from datetime import datetime

if os.name == "nt":
    import msvcrt
else:
    import fcntl

EXIT_TIMEOUT = 75
EXIT_LOCK_ERROR = 76
EXIT_COMMAND_NOT_FOUND = 77
TICKET_DIR = "tickets"
POLL_SECONDS = 1.0
PRINT_EVERY_SECONDS = 30.0
ENV_HELD = "NETSEC_HEAVY_LOCK_HELD"
LOCK_NAME = "heavy-run.lock"
INFO_NAME = "heavy-run.info"


def process_start(pid):
    """A string that identifies when this process started, or None when no such process exists. A process that exists but cannot be opened
    (access denied) counts as alive."""
    if os.name == "nt":
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, int(pid))              # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return "unknown-start" if ctypes.get_last_error() == 5 or kernel32.GetLastError() == 5 else None      # 5 = ERROR_ACCESS_DENIED
        try:
            created, exited, kernel, user = (ctypes.c_ulonglong() for _ in range(4))
            if not kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
                return "unknown-start"
            code = ctypes.c_ulong()
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value != 259:      # 259 = STILL_ACTIVE
                return None
            return str(created.value)
        finally:
            kernel32.CloseHandle(handle)
    try:
        return pathlib.Path(f"/proc/{int(pid)}/stat").read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def lock_dir(arg):
    if arg:
        return pathlib.Path(arg)
    if os.environ.get("NETSEC_LOCK_DIR"):
        return pathlib.Path(os.environ["NETSEC_LOCK_DIR"])
    base = os.environ.get("LOCALAPPDATA") or str(pathlib.Path.home() / ".cache")
    return pathlib.Path(base) / "mmp-netsec" / "locks"


class LockError(Exception):
    """An unexpected lock failure. It is never read as "free" and never as "held": the run stops with LOCK_ERROR (fail closed)."""


# What the OS says when ANOTHER process holds the byte: EACCES (a Windows lock violation reaches Python as this), EAGAIN (flock), EDEADLK and 36 (Windows).
CONTENDED = {errno.EACCES, errno.EAGAIN, errno.EDEADLK, 36}


def try_os_lock(fd):
    """True when this process now holds the exclusive lock (one byte at offset 0), False when another process holds it. Never blocks.
    Any other error raises LockError: the acquisition is the probe (gem probe-what-you-bind), and an unexpected error is not a verdict on availability."""
    try:
        if os.name == "nt":
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError as e:
        if e.errno in CONTENDED:
            return False
        raise LockError(f"the lock call failed unexpectedly: {e}") from e


def unlock(fd):
    try:
        if os.name == "nt":
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass


def read_info(directory):
    try:
        data = json.loads((directory / INFO_NAME).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and "pid" in data else None
    except (OSError, ValueError):
        return None


def describe(info):
    if not info:
        return "another heavy run (its details are not written yet)"
    started = str(info.get("started", "?"))[11:16] or "?"
    try:
        minutes = int((datetime.now() - datetime.fromisoformat(info["started"])).total_seconds() / 60)
        when = f"{minutes} min ago"
    except (KeyError, ValueError):
        when = "at an unknown time"
    return f"'{info.get('label', '?')}' (pid {info.get('pid')}, started {started}, {when})"


def open_lock(directory):
    try:
        directory.mkdir(parents=True, exist_ok=True)
        fd = os.open(directory / LOCK_NAME, os.O_RDWR | os.O_CREAT)
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")                                          # the locked byte must exist
        return fd
    except OSError as e:
        raise LockError(f"cannot open the lock file in {directory}: {e}") from e


def tie_children_to_this_process():
    """Windows: put this process in a job object that kills every member when this process ends. The command (and anything it starts) joins the job by
    inheritance, so a runner that dies (TaskStop, a crash) takes its heavy work with it. Without this the lock frees while the work keeps running,
    and a second heavy run starts on top of it. Fails closed: a job that cannot be made stops the run (LockError), never runs unprotected.
    POSIX: not covered here. A runner killed with SIGKILL leaves its command running (untested on this machine, noted in the PR)."""
    if os.name != "nt":
        return
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class BasicLimits(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

    class ExtendedLimits(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", ctypes.c_ulonglong * 6), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    job = kernel32.CreateJobObjectW(None, None)
    limits = ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = 0x2000                       # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    ok = job and kernel32.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)) and \
        kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess())
    if not ok:
        raise LockError(f"cannot tie the command to this runner with a job object: WinError {ctypes.get_last_error()}")
    # The job handle stays open until this process ends; closing it (at exit or by a kill) is what kills the members.


def make_ticket(directory):
    """A waiter's place in line: a file named by arrival time (nanoseconds, then pid), written under a temporary name and renamed, so a reader never
    sees a half-written ticket. The ticket only decides who MAY TRY the OS lock. The OS lock alone decides who holds it, so a wrong ticket costs
    fairness and can never put two runs in at once."""
    folder = directory / TICKET_DIR
    me = os.getpid()
    path = folder / f"{time.time_ns():020d}-{me}.json"
    try:
        folder.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps({"pid": me, "start": process_start(me)}), encoding="utf-8")
        os.replace(temp, path)
    except OSError as e:
        raise LockError(f"cannot write a ticket in {folder}: {e}") from e
    return path


def drop_ticket(path):
    try:
        path.unlink()
    except OSError:
        pass


def ticket_is_live(path):
    """True when the ticket names a process that is still the one that wrote it. Unreadable, junk and dead tickets count as not live."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        pid, start = data["pid"], data["start"]
    except (OSError, ValueError, KeyError, TypeError):
        return False
    return process_start(pid) == start


def earlier_live_tickets(directory, mine):
    """How many live waiters hold a ticket older than mine. Zero means it is my turn to try the lock."""
    count = 0
    for path in sorted((directory / TICKET_DIR).glob("*.json")):
        if path == mine:
            return count
        count += ticket_is_live(path)
    return count                                                      # my ticket is gone: do not block on others


def run(directory, label, wait_minutes, command):
    found = shutil.which(command[0])                                  # finds npm.cmd and .bat on Windows; never shell=True
    if found is None:
        print(f"COMMAND_NOT_FOUND: '{command[0]}' is not on PATH. Nothing ran and the lock was not touched.", flush=True)
        return EXIT_COMMAND_NOT_FOUND
    command = [found, *command[1:]]
    fd = open_lock(directory)
    tie_children_to_this_process()
    mine = make_ticket(directory)
    deadline = None if wait_minutes is None else time.time() + wait_minutes * 60
    last_print = 0.0
    env = dict(os.environ)
    held = False
    try:
        while True:
            info = read_info(directory)
            if info and os.environ.get(ENV_HELD) == str(info.get("pid")) and process_start(info["pid"]) is not None:
                print(f"HEAVY_LOCK already held by an ancestor: {describe(info)}", flush=True)
                break
            ahead = earlier_live_tickets(directory, mine)
            if ahead == 0 and try_os_lock(fd):
                held = True
                break
            if time.time() - last_print >= PRINT_EVERY_SECONDS:
                line = f"{ahead} earlier waiting run(s) first, then " if ahead else ""
                print(f"HEAVY_LOCK waiting on {line}{describe(info)}", flush=True)
                last_print = time.time()
            if deadline is not None and time.time() >= deadline:
                print(f"LOCK_TIMEOUT: still held by {describe(read_info(directory))} after {wait_minutes:g} min", flush=True)
                return EXIT_TIMEOUT
            time.sleep(POLL_SECONDS)
        drop_ticket(mine)                                             # a holder or ancestor-run is no longer in line
        if held:
            me = os.getpid()
            (directory / INFO_NAME).write_text(json.dumps({"pid": me, "label": label, "started": datetime.now().isoformat(timespec="seconds"),
                                                           "cwd": os.getcwd()}), encoding="utf-8")
            env[ENV_HELD] = str(me)
            print(f"HEAVY_LOCK taken by '{label}' (pid {me})", flush=True)
        return subprocess.run(command, env=env).returncode
    finally:
        drop_ticket(mine)
        if held:
            try:
                (directory / INFO_NAME).write_text("", encoding="utf-8")
            except OSError:
                pass
            unlock(fd)
        os.close(fd)


def status(directory):
    try:
        fd = open_lock(directory)
        try:
            if try_os_lock(fd):
                unlock(fd)
                print("heavy-run lock: free")
                return 0
            print(f"heavy-run lock: held by {describe(read_info(directory))}")
            return 2
        finally:
            os.close(fd)
    except LockError as e:
        print(f"LOCK_ERROR: {e}. The lock cannot be judged, so it is not reported as free.")
        return 1


def main(argv):
    try:
        return dispatch(argv)
    except LockError as e:
        print(f"LOCK_ERROR: {e}. The run stops here (fail closed): a lock that cannot be judged is neither free nor held.")
        return EXIT_LOCK_ERROR


def dispatch(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("action", choices=["status", "run"])
    ap.add_argument("--label", default="heavy run")
    ap.add_argument("--wait-minutes", type=float, default=None, help="give up after this long (default: wait without limit)")
    ap.add_argument("--lock-dir", default=None)
    args, rest = ap.parse_known_args(argv)
    directory = lock_dir(args.lock_dir)
    if args.action == "status":
        if rest:
            ap.error(f"unrecognized arguments: {' '.join(rest)}")
        return status(directory)
    command = rest[1:] if rest[:1] == ["--"] else rest
    if not command:
        print("usage: heavy_lock.py run --label L [--wait-minutes M] -- <command> [args]")
        return 2
    return run(directory, args.label, args.wait_minutes, command)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
