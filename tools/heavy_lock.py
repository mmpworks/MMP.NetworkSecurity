#!/usr/bin/env python3
"""A machine-wide lock for heavy runs: the full gate, the full app suite, acceptance runs, and load loops.

Why: ports are partitioned per run (NETSEC_PORT_BASE) but CPU is not. Heavy runs stacked on one machine pushed CPU to 100% and made product timing
tests fail in a different place each time (a test-host hang, a CE-READY timeout, a Host with no ready line in 60 s). One heavy run at a time removes
that noise. Small targeted runs stay unlocked. A load burner or a hang loop counts as a heavy run and takes the lock like a gate does.

  python -I tools/heavy_lock.py run --label "gate AppProof" [--wait-minutes M] -- <command> [args]   take the lock, run the command, release
  python -I tools/heavy_lock.py status                                                               exit 0 free, 2 held (names the holder)
  python -I tools/heavy_lock.py holds                                                                exit 0 only inside the live holder, else 1
  python -I tools/heavy_lock.py hold --label "bench window" --allow "richard" --minutes 60           start a hold (a quiet window)
  python -I tools/heavy_lock.py release                                                              end the hold

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

A hold is a quiet window, for a measurement that needs the whole machine. `hold` writes <lock dir>\\heavy-run.hold (label, allowed prefix, set time,
expiry). While the hold is active, a run whose label does not start with the allowed prefix waits, prints "HEAVY_LOCK held for window '<label>'
until HH:MM", and keeps its ticket. This holds for a run that starts in the window and for a waiter that queued before it. A run whose label starts
with the prefix proceeds as before, and it does not wait behind the waiters that the hold stops. With no --allow, no run proceeds.
1. A run that holds the lock when the hold starts goes on to its end. The hold stops the next taker, not the present holder.
2. Past its expiry a hold counts as gone, so a forgotten hold never stops the machine for ever. --minutes is at most 720.
3. A hold file that cannot be read stays closed for every run until its expiry, when the expiry can still be read. With no readable expiry, or
   an expiry more than 720 minutes ahead, the file is ignored (open). `status` says which.
4. `status` keeps its exit code (0 free, 2 held) and names the hold on a second line.
5. A window that runs longer than planned: set --minutes with a margin, and run `hold` again to extend it. A new `hold` replaces the old one.
6. A read of the hold file that the OS refuses (another process has the file) is tried 3 times, 50 ms apart. When all 3 fail, no run takes
   the lock on that pass, and `status` says the file cannot be read now. `hold` and `release` try a rename or a delete 5 times before they
   stop with LOCK_ERROR.
7. Any run can pass a hold with a label that starts with the prefix. The hold is a tool for runs that cooperate, not a guard.
8. Each worktree runs its own copy of this file. A copy from before the hold switch does not read the hold file, so a run started from such a
   worktree ignores the hold.
"""
import argparse
import ctypes
import errno
import json
import os
import pathlib
import re
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
HOLD_NAME = "heavy-run.hold"
MAX_HOLD_MINUTES = 720.0                                                # 12 hours: no quiet window is longer, so a larger expiry is a mistake
HOLD_IO_TRIES = 3                                                       # reads of the hold file before "unreadable"
HOLD_WRITE_TRIES = 5                                                    # renames or deletes of the hold file before LOCK_ERROR
HOLD_IO_PAUSE_SECONDS = 0.05


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


def read_hold_bytes(path):
    return path.read_bytes()


def retry_in_use(action):
    """Runs a write on the hold file again when Windows says the file is in use (a waiter reads it, a scanner has it). Python opens files
    without FILE_SHARE_DELETE, so a rename or a delete can meet a reader. The last PermissionError goes to the caller."""
    for attempt in range(HOLD_WRITE_TRIES):
        try:
            return action()
        except PermissionError:
            if attempt == HOLD_WRITE_TRIES - 1:
                raise
            time.sleep(HOLD_IO_PAUSE_SECONDS)


def read_hold(directory, now=None):
    """The hold (a quiet window) as a dict with "state" and, when it has them, "label", "allow" and "expires" (epoch seconds).
    States: "none" (no file); "active"; "expired" (past its expiry, so it counts as gone: a forgotten hold never stops the machine for ever);
    "closed" (the file cannot be read, but its expiry can, and that is in the future: the hold stays on until then, for every label);
    "open" (the content cannot be read and names no usable expiry, or the expiry is more than MAX_HOLD_MINUTES ahead: ignored);
    "unreadable" (the file exists and the OS refuses the read, 3 times: another process has it. No run takes the lock on that pass, because
    one failed read must not open a window. This lasts only while the file stays unreadable, and `status` names it)."""
    now = time.time() if now is None else now
    for attempt in range(HOLD_IO_TRIES):
        try:
            text = read_hold_bytes(directory / HOLD_NAME).decode("utf-8", errors="replace")
            break
        except FileNotFoundError:
            return {"state": "none"}
        except OSError as e:
            if attempt == HOLD_IO_TRIES - 1:
                return {"state": "unreadable", "why": f"the hold file cannot be read now ({e})"}
            time.sleep(HOLD_IO_PAUSE_SECONDS)
    try:
        data = json.loads(text)
        if not isinstance(data, dict) or isinstance(data.get("expires"), bool) or not isinstance(data.get("expires"), (int, float)):
            raise ValueError("no expiry")
        hold = {"state": "active", "label": str(data.get("label", "?")), "allow": str(data.get("allow") or ""), "expires": float(data["expires"])}
    except ValueError:
        found = re.search(r'"expires"\s*:\s*(?P<expires>\d+(?:\.\d+)?)', text)
        if not found:
            return {"state": "open", "why": "the hold file cannot be read and names no expiry"}
        hold = {"state": "closed", "label": "(a hold file that cannot be read)", "allow": "", "expires": float(found.group("expires"))}
    if hold["expires"] <= now:
        hold["state"] = "expired"
    elif hold["expires"] - now > MAX_HOLD_MINUTES * 60:
        return {"state": "open", "why": f"the hold file names an expiry more than {MAX_HOLD_MINUTES:g} minutes ahead"}
    return hold


def stops(hold, label):
    """True when this hold makes a run with this label wait. An empty allowed prefix lets no run through. A hold file that the OS refuses
    to read stops every label: its allowed prefix is unknown."""
    if hold["state"] == "unreadable":
        return True
    if hold["state"] not in ("active", "closed"):
        return False
    return not (hold["allow"] and label.startswith(hold["allow"]))


def held_text(hold):
    """What a stopped run prints after "HEAVY_LOCK " and after "LOCK_TIMEOUT: "."""
    if hold["state"] == "unreadable":
        return f"held: {hold['why']}; no run takes the lock while this lasts"
    return f"held for window '{hold['label']}' until {until(hold)}"


def until(hold):
    return datetime.fromtimestamp(hold["expires"]).strftime("%H:%M")


def describe_hold(hold):
    """The status line for a hold, or None when no hold file exists."""
    state = hold["state"]
    if state == "none":
        return None
    if state == "open":
        return f"heavy-run hold: {hold['why']}: ignored (open)"
    if state == "unreadable":
        return f"heavy-run hold: {hold['why']}: no run takes the lock while this lasts"
    if state == "expired":
        return f"heavy-run hold: '{hold['label']}' expired at {until(hold)}: it counts as gone"
    if state == "closed":
        return f"heavy-run hold: the hold file cannot be read, but its expiry can: closed until {until(hold)} for every run"
    allowed = f"only labels that start with '{hold['allow']}' run" if hold["allow"] else "no run is allowed"
    return f"heavy-run hold '{hold['label']}' until {until(hold)}: {allowed}"


def set_hold(directory, label, allow, minutes):
    if not 0 < minutes <= MAX_HOLD_MINUTES:
        print(f"usage: heavy_lock.py hold --label L [--allow PREFIX] --minutes N, with N above 0 and at most {MAX_HOLD_MINUTES:g}. No hold was written.")
        return 2
    now = time.time()
    data = {"label": label, "allow": allow or "", "set": datetime.fromtimestamp(now).isoformat(timespec="seconds"), "expires": now + minutes * 60,
            "until": datetime.fromtimestamp(now + minutes * 60).isoformat(timespec="seconds")}
    path = directory / HOLD_NAME
    try:
        directory.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(data), encoding="utf-8")
        retry_in_use(lambda: os.replace(temp, path))                     # a rename: a reader never sees a half-written hold
    except OSError as e:
        raise LockError(f"cannot write the hold file in {directory}: {e}") from e
    print(f"HEAVY_LOCK hold set: {describe_hold(read_hold(directory))}. A run that holds the lock now goes on to its end.")
    return 0


def release_hold(directory):
    try:
        retry_in_use(lambda: os.unlink(directory / HOLD_NAME))
    except FileNotFoundError:
        print("HEAVY_LOCK no hold was set")
        return 0
    except OSError as e:
        raise LockError(f"cannot remove the hold file in {directory}: {e}") from e
    print("HEAVY_LOCK hold released")
    return 0


def make_ticket(directory, label=""):
    """A waiter's place in line: a file named by arrival time (nanoseconds, then pid), written under a temporary name and renamed, so a reader never
    sees a half-written ticket. The ticket only decides who MAY TRY the OS lock. The OS lock alone decides who holds it, so a wrong ticket costs
    fairness and can never put two runs in at once. The label lets a run that a hold allows step past the waiters that the hold stops."""
    folder = directory / TICKET_DIR
    me = os.getpid()
    path = folder / f"{time.time_ns():020d}-{me}.json"
    try:
        folder.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps({"pid": me, "start": process_start(me), "label": label}), encoding="utf-8")
        os.replace(temp, path)
    except OSError as e:
        raise LockError(f"cannot write a ticket in {folder}: {e}") from e
    return path


def drop_ticket(path):
    try:
        path.unlink()
    except OSError:
        pass


def live_ticket_label(path):
    """The label of a ticket whose process is still the one that wrote it ("" when the ticket has none), or None. Unreadable, junk and dead
    tickets count as not live."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        pid, start = data["pid"], data["start"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return str(data.get("label") or "") if process_start(pid) == start else None


def ticket_is_live(path):
    return live_ticket_label(path) is not None


def earlier_live_tickets(directory, mine, hold=None):
    """How many live waiters hold a ticket older than mine. Zero means it is my turn to try the lock. With a hold, a waiter that the hold stops
    is not counted: it keeps its ticket and its place, and a run that the hold allows does not wait behind it."""
    count = 0
    for path in sorted((directory / TICKET_DIR).glob("*.json")):
        if path == mine:
            return count
        label = live_ticket_label(path)
        count += label is not None and not (hold is not None and stops(hold, label))
    return count                                                      # my ticket is gone: do not block on others


def names_live_holder(info):
    """True when NETSEC_HEAVY_LOCK_HELD holds the pid the info file names and that process is alive. The caller must also know the lock is held."""
    return bool(info) and os.environ.get(ENV_HELD) == str(info.get("pid")) and process_start(info["pid"]) is not None


def holds(directory):
    """Exit 0 only when this process runs inside the live holder: the lock is really held and NETSEC_HEAVY_LOCK_HELD names that holder.
    Callers (gate.ps1, acceptance/run.ps1) skip taking the lock on 0 and take it on anything else, so a shell with a stale inherited
    variable cannot bypass the lock."""
    fd = open_lock(directory)
    try:
        if try_os_lock(fd):
            unlock(fd)
            print("heavy-run lock: not held, so no run is a holder")
            return 1
        if names_live_holder(read_info(directory)):
            print(f"heavy-run lock: this process runs inside the holder {describe(read_info(directory))}")
            return 0
        print("heavy-run lock: held by another run; NETSEC_HEAVY_LOCK_HELD does not name it")
        return 1
    finally:
        os.close(fd)


def run(directory, label, wait_minutes, command):
    found = shutil.which(command[0])                                  # finds npm.cmd and .bat on Windows; never shell=True
    if found is None:
        print(f"COMMAND_NOT_FOUND: '{command[0]}' is not on PATH. Nothing ran and the lock was not touched.", flush=True)
        return EXIT_COMMAND_NOT_FOUND
    command = [found, *command[1:]]
    fd = open_lock(directory)
    tie_children_to_this_process()
    mine = make_ticket(directory, label)
    deadline = None if wait_minutes is None else time.time() + wait_minutes * 60
    last_print = 0.0
    last_stopped = None
    env = dict(os.environ)
    held = False
    try:
        while True:
            info = read_info(directory)
            if names_live_holder(info):
                print(f"HEAVY_LOCK already held by an ancestor: {describe(info)}", flush=True)
                break
            # The hold is read on every pass, so a waiter that queued before the hold began also obeys it (the case of 2026-11-11, 20:12).
            hold = read_hold(directory)
            stopped = stops(hold, label)
            ahead = 0 if stopped else earlier_live_tickets(directory, mine, hold)
            if not stopped and ahead == 0 and try_os_lock(fd):
                held = True
                break
            if stopped != last_stopped or time.time() - last_print >= PRINT_EVERY_SECONDS:      # a hold that begins or ends is named at once
                if stopped:
                    print(f"HEAVY_LOCK {held_text(hold)}; this run keeps its place in line", flush=True)
                else:
                    line = f"{ahead} earlier waiting run(s) first, then " if ahead else ""
                    print(f"HEAVY_LOCK waiting on {line}{describe(info)}", flush=True)
                last_print = time.time()
                last_stopped = stopped
            if deadline is not None and time.time() >= deadline:
                if stopped:
                    print(f"LOCK_TIMEOUT: {held_text(hold)}, after {wait_minutes:g} min", flush=True)
                else:
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
        print(f"HEAVY_LOCK launching {json.dumps(command)}", flush=True)         # the argv as it reaches the OS, so a rewritten command line shows in the log
        code = subprocess.run(command, env=env).returncode
        print(f"HEAVY_LOCK finished exit {code}", flush=True)                        # tools/run_status.py reads this to tell an exited run from a running one
        return code
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
    """Exit 0 free, 2 held: the code judges the lock only. A hold is named on a second line and does not change the code."""
    try:
        fd = open_lock(directory)
        try:
            if try_os_lock(fd):
                unlock(fd)
                print("heavy-run lock: free")
                code = 0
            else:
                print(f"heavy-run lock: held by {describe(read_info(directory))}")
                code = 2
            line = describe_hold(read_hold(directory))
            if line:
                print(line)
            return code
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
    ap.add_argument("action", choices=["status", "run", "holds", "hold", "release"])
    ap.add_argument("--label", default="heavy run")
    ap.add_argument("--wait-minutes", type=float, default=None, help="give up after this long (default: wait without limit)")
    ap.add_argument("--lock-dir", default=None)
    ap.add_argument("--allow", default="", help="hold: the label prefix that may run during the hold (default: no run)")
    ap.add_argument("--minutes", type=float, default=None, help="hold: how long the hold lasts")
    args, rest = ap.parse_known_args(argv)
    directory = lock_dir(args.lock_dir)
    if args.action in ("status", "holds", "hold", "release"):
        if rest:
            ap.error(f"unrecognized arguments: {' '.join(rest)}")
        if args.action == "hold":
            return set_hold(directory, args.label, args.allow, args.minutes if args.minutes is not None else 0.0)
        if args.action == "release":
            return release_hold(directory)
        return status(directory) if args.action == "status" else holds(directory)
    command = rest[1:] if rest[:1] == ["--"] else rest
    if not command:
        print("usage: heavy_lock.py run --label L [--wait-minutes M] -- <command> [args]")
        return 2
    return run(directory, args.label, args.wait_minutes, command)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
