#!/usr/bin/env python3
"""Fail when a change to acceptance/ also touches anything outside acceptance/ and docs/.

acceptance/ belongs to the suite's own authors (builders never write there), and its PIN names one tree hash. A PR that mixes acceptance/ with product
code makes the PIN, the review and the revert all harder, so a change that touches acceptance/ may touch only acceptance/ and docs/.

The file set is what git reports for the change: `git diff --name-only --no-renames origin/main...HEAD` plus `git status --porcelain --no-renames`
(uncommitted and untracked files count). --no-renames lists a rename as a delete of the old path plus an add of the new one, so moving app/x into
acceptance/x names app/x. When origin/main is unknown, or a git call fails (an unborn HEAD, a broken index), the check fails closed with a named
code. A change with no file under acceptance/ passes whatever it touches.

Note: untracked files count, so a scratch file left at the top of the tree or in tools/ fails the check for an acceptance/ change. That is the safe
direction, and the message names the path.

--base REF names the ref to diff against (default origin/main). Run after a merge, origin/main...HEAD is empty and the check would judge nothing, so
use the merge's first parent: `--base <merge>^1`. When the file set is empty the check prints a first line starting `SKIP:` (the gate reads that as a
SKIPPED row, never PASS) and exits 0.

Usage: python -I tools/check_acceptance_scope.py [--root REPO] [--base REF]. Exit 0 when in scope or when nothing changed, 1 otherwise.
"""
import argparse
import pathlib
import subprocess
import sys

BASE = "origin/main"
ALLOWED = ("acceptance/", "docs/")


class GitFailed(Exception):
    pass


def git(root, *args):
    r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr.strip()


def git_must(root, *args):
    """Stdout of a git call that has to work. A failure raises instead of returning an empty list, because an empty file set passes the check."""
    code, out, err = git(root, *args)
    if code != 0:
        raise GitFailed(f"git {' '.join(args)} exited {code}: {err or 'no message'}")
    return out


def changed_files(root, base=BASE):
    """The set of paths in the change, or None when the base ref is unknown. Raises GitFailed when a git call fails."""
    code, _, _ = git(root, "rev-parse", "--verify", "-q", base)
    if code != 0:
        return None
    names = set()
    out = git_must(root, "diff", "--name-only", "--no-renames", f"{base}...HEAD")
    names.update(line.strip() for line in out.splitlines() if line.strip())
    out = git_must(root, "status", "--porcelain", "--no-renames", "--untracked-files=all")   # all: name the file, not its untracked folder
    for line in out.splitlines():
        if len(line) > 3:
            names.add(line[3:].strip().strip('"'))
    return names


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parent.parent))
    ap.add_argument("--base", default=BASE, help="ref to diff against; after a merge use <merge>^1")
    args = ap.parse_args(argv)
    try:
        files = changed_files(args.root, args.base)
    except GitFailed as e:
        print(f"ACCEPTANCE_SCOPE_GIT_FAILED: {e}. The change cannot be judged, so the check fails closed.")
        return 1
    if files is None:
        print(f"ACCEPTANCE_SCOPE: {args.base} is unknown here, so the change cannot be judged and the check fails closed. Run: git fetch origin")
        return 1
    if not files:
        print(f"SKIP: no changed file against {args.base}, so the scope rule judged nothing (after a merge, pass --base <merge>^1)")
        return 0
    if not any(f.startswith("acceptance/") for f in files):
        print("no file under acceptance/ changed, so the scope rule does not apply")
        return 0
    outside = sorted(f for f in files if not f.startswith(ALLOWED))
    for path in outside:
        print(f"ACCEPTANCE_SCOPE: {path} is outside acceptance/ and docs/. A change to acceptance/ may touch only those two folders; move this file to its own PR.")
    if outside:
        return 1
    print(f"acceptance/ changed in a change that stays inside acceptance/ and docs/ ({len(files)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
