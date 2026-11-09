#!/usr/bin/env python3
"""Print one line that says how a background run is doing, from its log file.

Why: a run's finish notice reached an agent late or never, four times in one day, costing about an hour each time. Read the log at the
run's expected end instead of waiting on the notice (docs/program-design.md section 9.1).

Usage: python tools/run_status.py LOGFILE [--stuck-after MINUTES]   (default 10)

Output and exit code:
  PASSED  <summary>            0   the run finished and everything passed
  FAILED  <summary>            1   the run finished with failures
  RUNNING <where> ...          2   still writing; names the current step or the count so far
  STUCK   at <where> ...       3   no output for more than --stuck-after minutes and no final line
  NO_LOG  <path>               4   the file does not exist

It reads the three log shapes this repo produces: tools/gate.ps1 (`== step` lines, `gate X: N of M steps passed`, `gate exit N`),
Playwright (`N passed (time)`, `N failed`, `N did not run`), and dotnet test (`Passed!`/`Failed!  - Failed: a, Passed: b, ... Total: c`).
"""
import argparse
import os
import re
import sys
import time

ANSI = re.compile(r"\x1b\[[0-9;]*m")
GATE_FINAL = re.compile(r"^gate (?P<slice>\S+?): (?P<n>\d+) of (?P<m>\d+) steps passed(?:, (?P<k>\d+) skipped)?", re.M)
GATE_EXIT = re.compile(r"^gate exit (?P<code>\d+)", re.M)
# The commit a run was made on: tools/gate.ps1 prints "gate <slice> @ <sha>[+dirty]" first, and the Playwright globalSetup prints "run @ <sha>[+dirty]".
HEAD_LINE = re.compile(r"^(?:gate \S+|run) @ (?P<head>[0-9a-f]+(?:\+dirty)?|unknown)\s*$", re.M)
HEAVY_FINISHED = re.compile(r"^HEAVY_LOCK finished exit (?P<code>-?\d+)\s*$", re.M)
GATE_STEP = re.compile(r"^== (?P<name>.+?)(?::.*)?$", re.M)
PW_PASSED = re.compile(r"^\s*(?P<n>\d+) passed \(", re.M)
PW_FAILED = re.compile(r"^\s*(?P<n>\d+) failed\s*$", re.M)
PW_NOT_RUN = re.compile(r"^\s*(?P<n>\d+) did not run\s*$", re.M)
PW_DONE_TESTS = re.compile(r"^\s*(?:ok|x)\s+(?P<i>\d+) ", re.M)
PW_TOTAL = re.compile(r"^Running (?P<n>\d+) tests", re.M)
DOTNET_FINAL = re.compile(r"^(?P<verdict>Passed|Failed)!\s+- Failed:\s+(?P<failed>\d+), Passed:\s+(?P<passed>\d+), Skipped:\s+\d+, Total:\s+(?P<total>\d+)", re.M)
DOTNET_ANNOUNCED = re.compile(r"^Test run for ", re.M)


def final_line(text):
    """(verdict, summary) when the log holds a final line, else None. verdict is PASSED or FAILED.

    A log with any `== step` line is a gate log, and only the gate's own summary or exit line can end it: the dotnet test results inside
    it arrive long before the gate is done (Jared, #265). A dotnet test log counts every `Test run for` line as one run (one per target
    framework) and is final only when each announced run has a result line, whose counts are summed."""
    if GATE_STEP.search(text):
        gate = GATE_FINAL.search(text)
        code = GATE_EXIT.search(text)
        if gate:
            n, m = int(gate["n"]), int(gate["m"])
            ok = n == m and (code is None or code["code"] == "0")
            return ("PASSED" if ok else "FAILED", f"gate {gate['slice']}: {n} of {m} steps passed" + (f", {gate['k']} skipped" if gate["k"] else "") + (f", exit {code['code']}" if code else ""))
        if code:
            return ("PASSED" if code["code"] == "0" else "FAILED", f"gate exit {code['code']}")
        return None
    results = list(DOTNET_FINAL.finditer(text))
    announced = len(DOTNET_ANNOUNCED.findall(text))
    if results and len(results) >= announced:
        passed = sum(int(r["passed"]) for r in results)
        total = sum(int(r["total"]) for r in results)
        failed = sum(int(r["failed"]) for r in results)
        ok = failed == 0 and all(r["verdict"] == "Passed" for r in results)
        return ("PASSED" if ok else "FAILED", f"dotnet test: {passed} of {total} passed, {failed} failed")
    passed = PW_PASSED.search(text)
    failed = PW_FAILED.search(text)
    if passed or failed:
        parts = [f"{failed['n']} failed"] if failed else []
        not_run = PW_NOT_RUN.search(text)
        if not_run:
            parts.append(f"{not_run['n']} did not run")
        parts.append(f"{passed['n']} passed" if passed else "0 passed")
        return ("FAILED" if failed or not_run else "PASSED", "playwright: " + ", ".join(parts))
    return None


def finished_line(text):
    """(FAILED, summary) for a run that has exited with no result line of its own, else None.

    tools/heavy_lock.py prints `HEAVY_LOCK finished exit N` when its command ends. A command that died on a config or startup error (a
    Playwright config that throws, a missing build) prints a stack trace and no `N passed`, so without this line the log read RUNNING for ever.
    Exit 0 with no result line is also FAILED: nothing in the log shows a test ran."""
    done = None
    for done in HEAVY_FINISHED.finditer(text):               # the last one: a nested run (npm run e2e inside a held lock) prints its own finish line mid-log
        pass
    if not done or text[done.end():].strip():                # more output after it means an outer run is still going
        return None
    code = done["code"]
    before = [line.strip() for line in text[:done.start()].splitlines() if line.strip()]
    error = next((line for line in reversed(before) if line.startswith(("Error", "error", "Traceback", "Exception"))), before[-1] if before else "no output")
    if code == "0":
        return ("FAILED", "run exited 0 but the log holds no result line")
    return ("FAILED", f"run exited {code}: {error[:120]}")


def where(text):
    """Where a run that has not finished is: the current gate step, or the Playwright count so far."""
    steps = GATE_STEP.findall(text)
    if steps:
        return steps[-1]
    announced = len(DOTNET_ANNOUNCED.findall(text))
    if announced:
        return f"dotnet test run {len(DOTNET_FINAL.findall(text))} of {announced} finished"
    done = PW_DONE_TESTS.findall(text)
    total = PW_TOTAL.search(text)
    if done or total:
        return f"playwright test {done[-1] if done else 0}" + (f" of {total['n']}" if total else "")
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1].strip()[:80] if lines else "no output yet"


def main(argv):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")     # a log line may hold a check mark; a cp1252 console must not crash the tool
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("log")
    ap.add_argument("--stuck-after", type=float, default=10.0, help="minutes without output before the run counts as stuck")
    args = ap.parse_args(argv)
    if not os.path.isfile(args.log):
        print(f"NO_LOG  {args.log}")
        return 4
    text = ANSI.sub("", open(args.log, encoding="utf-8", errors="replace").read())
    head = HEAD_LINE.search(text)
    commit = f" @ {head['head']}" if head else ""
    done = final_line(text) or finished_line(text)
    if done:
        print(f"{done[0]}  {done[1]}{commit}")
        return 0 if done[0] == "PASSED" else 1
    quiet = (time.time() - os.path.getmtime(args.log)) / 60
    here = where(text)
    if quiet > args.stuck_after:
        print(f"STUCK   at {here}; no output for {quiet:.0f} min (limit {args.stuck_after:g}){commit}")
        return 3
    print(f"RUNNING {here}; last output {quiet:.0f} min ago{commit}")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
