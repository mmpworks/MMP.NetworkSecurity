"""acceptance/PIN: the id of the last approved acceptance/ state, kept current by every PR that changes acceptance/.

  python -I acceptance/tools/pin.py --check   exit 0 when PIN matches HEAD's acceptance/ tree; exit 1 with a reason code and the fix
  python -I acceptance/tools/pin.py --write   write the id for HEAD's acceptance/ tree into acceptance/PIN (commit it next)

The id is a git tree hash of HEAD:acceptance with the PIN entry left out, written as "acceptance-tree <hash>". A PR cannot know the commit it
will merge as, and a commit cannot name itself, so PIN names the tree instead (the same move as app/dist's tree stamp). PIN is left out, so a
commit that changes only PIN keeps the id it wrote. The PIN had held a commit, and it went stale across many PRs because only a -Fresh run
looked at it (2026-11-08); the gate now runs --check on every PR.

Reason codes: PIN_UNSET, PIN_OLD_FORM (a bare commit id), PIN_STALE, UNCOMMITTED (on --write), NO_GIT.
"""
import argparse
import pathlib
import subprocess
import sys

PREFIX = "acceptance-tree "
FIX = "python -I acceptance/tools/pin.py --write, then commit acceptance/PIN"


def git(root, *args, stdin=None):
    # Bytes on the pipe, never text mode: on Windows text mode writes \r\n, and git mktree then builds a tree with other names, so the id
    # would differ by OS (test_id_equals_gits_own_tree_id_when_no_pin_exists).
    r = subprocess.run(["git", "-C", str(root), *args], input=stdin.encode("utf-8") if stdin is not None else None, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.decode('utf-8', 'replace').strip()}")
    return r.stdout.decode("utf-8")


def acceptance_tree(root):
    """The tree hash of HEAD:acceptance without its top-level PIN entry. git mktree builds the tree object from ls-tree lines, so the id
    equals what git would give a commit whose acceptance/ held no PIN."""
    # -z on both sides: entries end in NUL, so a file name that holds a tab or a newline cannot shift the id.
    entries = [e for e in git(root, "ls-tree", "-z", "HEAD:acceptance").split("\0") if e and e.split("\t", 1)[-1] != "PIN"]
    return git(root, "mktree", "-z", stdin="".join(e + "\0" for e in entries)).strip()


def read_pin(root):
    path = pathlib.Path(root) / "acceptance" / "PIN"
    return path.read_text(encoding="utf-8").strip() if path.exists() else ""


def check(root):
    have = read_pin(root)
    if not have:
        return 1, f"PIN_UNSET: acceptance/PIN is missing or empty. Fix: {FIX}"
    if not have.startswith(PREFIX):
        return 1, f"PIN_OLD_FORM: acceptance/PIN holds '{have[:12]}', a commit id, not '{PREFIX}<hash>'. Fix: {FIX}"
    want = PREFIX + acceptance_tree(root)
    if have != want:
        return 1, (f"PIN_STALE: acceptance/ changed since acceptance/PIN was written. PIN has '{have}', HEAD's acceptance/ is '{want}'. "
                   f"A PR that changes acceptance/ bumps PIN in the same PR. Fix: {FIX}")
    return 0, f"acceptance/PIN is current: {want}"


def write(root):
    dirty = [line for line in git(root, "status", "--porcelain", "--untracked-files=no", "--", "acceptance").splitlines()
             if not line.rstrip().endswith("acceptance/PIN")]
    if dirty:
        return 1, "UNCOMMITTED: commit the acceptance/ edits first, so PIN names what will be pushed: " + "; ".join(d.strip() for d in dirty[:5])
    value = PREFIX + acceptance_tree(root)
    (pathlib.Path(root) / "acceptance" / "PIN").write_text(value + "\n", encoding="utf-8", newline="\n")
    return 0, f"acceptance/PIN = {value}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parents[2]))
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    a = ap.parse_args()
    try:
        code, msg = check(a.root) if a.check else write(a.root)
    except RuntimeError as e:
        code, msg = 1, f"NO_GIT: {e}"
    print(msg)
    return code


if __name__ == "__main__":
    sys.exit(main())
