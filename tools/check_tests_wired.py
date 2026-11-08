#!/usr/bin/env python3
"""Fail when a tools/**/test_*.py file has no step in tools/gate.ps1.

Why: gate-adjacent test files landed with no gate step three times (#271, #277, #307), so the gate's own decision logic went untested on every
run until a reviewer noticed. A step counts when the file path (or its name, as a whole word) appears on a gate.ps1 line that is not a comment.

Usage: python -I tools/check_tests_wired.py [--root REPO]. Exit 0 when every test file has a step, 1 otherwise.
"""
import argparse
import pathlib
import re
import sys


def gate_lines(gate):
    """The lines of gate.ps1 that can hold a step: everything except full-line comments."""
    return [line for line in gate.read_text(encoding="utf-8", errors="replace").splitlines() if not line.lstrip().startswith("#")]


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parent.parent))
    args = ap.parse_args(argv)
    root = pathlib.Path(args.root)
    gate = root / "tools" / "gate.ps1"
    if not gate.is_file():
        print(f"TEST_UNWIRED: {gate.as_posix()} does not exist, so no test has a gate step.")
        return 1
    lines = gate_lines(gate)
    missing = []
    for path in sorted((root / "tools").rglob("test_*.py")):
        name = re.escape(path.name)
        # The name must stand alone: not part of a longer file name such as other_test_a.py or test_a.py.bak.
        pattern = re.compile(rf"(?<![\w.-]){name}(?![\w.-])")
        if not any(pattern.search(line) for line in lines):
            missing.append(path.relative_to(root).as_posix())
    for rel in missing:
        print(f"TEST_UNWIRED: {rel} has no step in tools/gate.ps1. Add: Step '{pathlib.PurePosixPath(rel).stem} tests' {{ python -I {rel} }}")
    if missing:
        return 1
    print("every tools/**/test_*.py has a step in tools/gate.ps1")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
