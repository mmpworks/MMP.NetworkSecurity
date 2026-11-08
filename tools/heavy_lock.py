#!/usr/bin/env python3
"""A machine-wide lock for heavy runs: the full gate, the full app suite, acceptance runs, and load loops.

Why: ports are partitioned per run (NETSEC_PORT_BASE) but CPU is not. Heavy runs stacked on one machine pushed CPU to 100% and made product timing
tests fail in a different place each time (a test-host hang, a CE-READY timeout, a Host with no ready line in 60 s). One heavy run at a time removes
that noise. Small targeted runs stay unlocked. A load burner or a hang loop counts as a heavy run and takes the lock like a gate does.

  python -I tools/heavy_lock.py run --label "gate AppProof" -- pwsh -File tools/gate.ps1 ...   take the lock, run the command, release (exit code passes through)
  python -I tools/heavy_lock.py acquire --label L [--pid N] [--wait-minutes M]                  take the lock for a process (default: this one's parent)
  python -I tools/heavy_lock.py release [--pid N]                                               release it (only the holder may)
  python -I tools/heavy_lock.py status                                                          exit 0 free, 2 held

The lock is one JSON file (pid, process start time, label, start time) under %LOCALAPPDATA%\\mmp-netsec\\locks (NETSEC_LOCK_DIR or --lock-dir
override). A waiter prints "HEAVY_LOCK waiting on '<label>' (pid N, started HH:MM, M min ago)" at once and every 30 seconds. A holder whose process
is gone, or whose pid now belongs to a process with a different start time, is stale: the next run replaces it, so a crash needs no cleanup.
`run` sets NETSEC_HEAVY_LOCK_HELD=<holder pid> for its command; a run started inside a holder (the gate's own app suite) proceeds without waiting.
Exit codes: 0 ok, 1 not held / error, 2 status held, 75 LOCK_TIMEOUT.
"""
import argparse
import ctypes
import json
import os
import pathlib
import subprocess
import sys
import time
from datetime import datetime

EXIT_TIMEOUT = 75
POLL_SECONDS = 1.0
PRINT_EVERY_SECONDS = 30.0
ENV_HELD = "NETSEC_HEAVY_LOCK_HELD"
LOCK_NAME = "heavy-run.lock"


def process_start(pid):
    """A string that identifies when this process started (so a reused pid is told apart), or None when the process does not exist."""
    if os.name == "nt":
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, int(pid))              # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return None
        try:
            created, exited, kernel, user = (ctypes.c_ulonglong() for _ in range(4))
            if not kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
                return None
            code = ctypes.c_ulong()
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value != 259:      # 259 = STILL_ACTIVE
                return None
            return str(created.value)
        finally:
            kernel32.CloseHandle(handle)
    try:
        stat = pathlib.Path(f"/proc/{int(pid)}/stat").read_text().rsplit(")", 1)[1].split()
        return stat[19]
    except (OSError, IndexError):
        return None


def lock_dir(arg):
    if arg:
        return pathlib.Path(arg)
    if os.environ.get("NETSEC_LOCK_DIR"):
        return pathlib.Path(os.environ["NETSEC_LOCK_DIR"])
    base = os.environ.get("LOCALAPPDATA") or str(pathlib.Path.home() / ".cache")
    return pathlib.Path(base) / "mmp-netsec" / "locks"


def read_holder(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def is_stale(holder):
    if not isinstance(holder, dict) or "pid" not in holder:
        return True
    return process_start(holder["pid"]) != holder.get("start")


def ago(holder):
    try:
        minutes = int((datetime.now() - datetime.fromisoformat(holder["started"])).total_seconds() / 60)
        return f"{minutes} min ago"
    except (KeyError, ValueError):
        return "at an unknown time"


def describe(holder):
    started = str(holder.get("started", "?"))[11:16] or "?"
    return f"'{holder.get('label', '?')}' (pid {holder.get('pid')}, started {started}, {ago(holder)})"


def try_create(path, pid, label):
    """Create the lock file for pid. False when it exists."""
    start = process_start(pid)
    if start is None:
        raise SystemExit(f"HEAVY_LOCK cannot take the lock for pid {pid}: no such process")
    body = json.dumps({"pid": pid, "start": start, "label": label, "started": datetime.now().isoformat(timespec="seconds"), "cwd": os.getcwd()})
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(body)
    return True


def acquire(directory, label, pid, wait_minutes):
    """0 when taken (or already held by an ancestor), EXIT_TIMEOUT after the wait limit."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / LOCK_NAME
    deadline = None if wait_minutes is None else time.time() + wait_minutes * 60
    last_print = 0.0
    while True:
        if try_create(path, pid, label):
            print(f"HEAVY_LOCK taken by '{label}' (pid {pid})", flush=True)
            return 0
        holder = read_holder(path)
        if is_stale(holder):
            print(f"HEAVY_LOCK stale lock from {describe(holder) if isinstance(holder, dict) else 'an unreadable file'}: its process is gone, replacing it", flush=True)
            try:
                os.replace(path, path.with_suffix(f".stale.{os.getpid()}"))
                os.remove(path.with_suffix(f".stale.{os.getpid()}"))
            except OSError:
                pass                                                      # another waiter replaced it first; the loop retries
            continue
        if os.environ.get(ENV_HELD) == str(holder.get("pid")):
            print(f"HEAVY_LOCK already held by an ancestor: {describe(holder)}", flush=True)
            return 0
        if time.time() - last_print >= PRINT_EVERY_SECONDS:
            print(f"HEAVY_LOCK waiting on {describe(holder)}", flush=True)
            last_print = time.time()
        if deadline is not None and time.time() >= deadline:
            print(f"LOCK_TIMEOUT: still held by {describe(holder)} after {wait_minutes:g} min", flush=True)
            return EXIT_TIMEOUT
        time.sleep(POLL_SECONDS)


def release(directory, pid):
    path = directory / LOCK_NAME
    holder = read_holder(path) if path.exists() else None
    if holder is None or holder.get("pid") != pid:
        print(f"LOCK_NOT_HELD: pid {pid} does not hold the lock" + (f" ({describe(holder)} does)" if isinstance(holder, dict) else ""))
        return 1
    os.remove(path)
    print(f"HEAVY_LOCK released by pid {pid}")
    return 0


def run(directory, label, wait_minutes, command):
    me = os.getpid()
    code = acquire(directory, label, me, wait_minutes)
    if code != 0:
        return code
    held_here = (directory / LOCK_NAME).exists() and (read_holder(directory / LOCK_NAME) or {}).get("pid") == me
    env = dict(os.environ)
    if held_here:
        env[ENV_HELD] = str(me)
    try:
        return subprocess.run(command, env=env).returncode
    finally:
        if held_here:
            release(directory, me)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("action", choices=["acquire", "release", "status", "run"])
    ap.add_argument("--label", default="heavy run")
    ap.add_argument("--pid", type=int, default=None)
    ap.add_argument("--wait-minutes", type=float, default=None, help="give up after this long (default: wait without limit)")
    ap.add_argument("--lock-dir", default=None)
    args, rest = ap.parse_known_args(argv)
    directory = lock_dir(args.lock_dir)
    if args.action == "run":
        command = rest[1:] if rest[:1] == ["--"] else rest
        if not command:
            print("usage: heavy_lock.py run --label L -- <command> [args]")
            return 2
        return run(directory, args.label, args.wait_minutes, command)
    if rest:
        ap.error(f"unrecognized arguments: {' '.join(rest)}")
    if args.action == "status":
        holder = read_holder(directory / LOCK_NAME) if (directory / LOCK_NAME).exists() else None
        if holder is None or is_stale(holder):
            print("heavy-run lock: free")
            return 0
        print(f"heavy-run lock: held by {describe(holder)}")
        return 2
    pid = args.pid if args.pid is not None else os.getppid()
    if args.action == "acquire":
        return acquire(directory, args.label, pid, args.wait_minutes)
    return release(directory, pid)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
