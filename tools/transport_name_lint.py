#!/usr/bin/env python3
"""Fail when app/src still uses "real", the old name of the os transport.

Why: the os transport was first called "real". The Host refuses "real" by name (TRANSPORT_UNKNOWN, pinned by
HostLiveTests.Unbuilt_lesson_and_real_mode_answer_by_code), so an app line that still sends it fails at run time. This lint catches the line
before that. It moved here from a Host test, which read app source from the wrong suite (test weeding survey, Host row 3).

Scans every .ts and .vue file under app/src. A hit is a quoted 'real' or "real", or the word isReal. app/src/types.ts must name 'os'.
Usage: python -I tools/transport_name_lint.py [--root REPO]. Exit 0 clean, 1 on a hit or a missing name.
"""
import argparse
import pathlib
import re
import sys

OLD = re.compile(r"""['"]real['"]|\bisReal\b""")
SUFFIXES = {".ts", ".vue"}


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parent.parent))
    args = ap.parse_args(argv)
    root = pathlib.Path(args.root)
    src = root / "app" / "src"
    if not src.is_dir():
        print(f"TRANSPORT_NAME_NO_APP: {src.as_posix()} is missing.")
        return 1
    hits = []
    for path in sorted(p for p in src.rglob("*") if p.is_file() and p.suffix in SUFFIXES):
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if OLD.search(line):
                hits.append(f"TRANSPORT_OLD_NAME: {path.relative_to(root).as_posix()}:{number}: {line.strip()[:120]}")
    types = src / "types.ts"
    if not types.is_file() or "'os'" not in types.read_text(encoding="utf-8", errors="replace"):
        hits.append("TRANSPORT_OS_NOT_NAMED: app/src/types.ts does not name 'os'.")
    if hits:
        print("\n".join(hits))
        print("The os transport is named 'os'. The Host refuses 'real' with TRANSPORT_UNKNOWN.")
        return 1
    print("app/src names the os transport 'os' and never 'real'")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
