#!/usr/bin/env python
"""Writes docs/_runs/lessons.json from the newest acceptance run and the tour files (D12). The Host reads it for lastRun.

Usage: python tools/lessons_status.py docs/_runs
"""
import glob
import json
import os
import re
import sys

LESSONS = range(0, 12)


def newest_summary(runs):
    paths = sorted(glob.glob(os.path.join(runs, "acceptance-*.json")))
    if not paths:
        return None
    with open(paths[-1], encoding="utf-8-sig") as handle:
        return json.load(handle).get("summary")


def main(runs):
    root = os.path.dirname(os.path.dirname(os.path.abspath(runs)))
    tours = os.path.join(root, "app", "src", "tours")
    present = set()
    if os.path.isdir(tours):
        for name in os.listdir(tours):
            match = re.match(r"^lesson-(?P<n>\d+)\.json$", name)
            if match:
                present.add(int(match.group("n")))
    summary = newest_summary(runs)
    rows = [{"lesson": n, "tour": n in present, "acceptance": summary} for n in LESSONS]
    out = os.path.join(runs, "lessons.json")
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        json.dump({"schema": 1, "lessons": rows}, handle, indent=1)
    print("lessons_status: %d tours of %d lessons; wrote %s" % (len(present), len(rows), out))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: lessons_status.py <runs folder>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
