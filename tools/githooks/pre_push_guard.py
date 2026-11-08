#!/usr/bin/env python3
"""pre-push guard: refuse a push to a branch whose pull requests are all MERGED or CLOSED.

A push to such a branch reaches nobody's review. It happened six times on this repo (among them #247, #197, #204), each time after the agent
printed the PR state and pushed anyway. Git runs this through tools/githooks/pre-push once tools/bootstrap.ps1 has set
core.hooksPath, so the stop is mechanical.

Rule: for each branch ref being pushed, ask `gh pr list --head <branch> --state all`. Refuse when the list is not empty and no PR is OPEN.
Allowed without asking gh: a branch delete, a tag, main and master (other gates own those). A branch with no PR is a new branch and passes.
When gh cannot answer (not installed, not signed in, offline), the guard refuses and says why.
"""
import json
import shutil
import subprocess
import sys

ZERO_SHA = "0" * 40
SKIPPED_BRANCHES = {"main", "master"}


class GhError(Exception):
    pass


def branches_pushed(lines):
    """Branch names git is about to create or update. Git feeds: <local ref> <local sha> <remote ref> <remote sha>."""
    for line in lines:
        parts = line.split()
        if len(parts) != 4:
            continue
        _, local_sha, remote_ref, _ = parts
        if not remote_ref.startswith("refs/heads/") or local_sha == ZERO_SHA:
            continue
        branch = remote_ref[len("refs/heads/"):]
        if branch not in SKIPPED_BRANCHES:
            yield branch


def prs_for(branch):
    gh = shutil.which("gh")
    if gh is None:
        raise GhError("gh is not on PATH")
    try:
        r = subprocess.run([gh, "pr", "list", "--head", branch, "--state", "all", "--json", "number,state", "--limit", "30"],
                           capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        raise GhError("gh took longer than 60 s")
    if r.returncode != 0:
        raise GhError((r.stderr or r.stdout).strip()[:200] or f"gh exited {r.returncode}")
    try:
        return json.loads(r.stdout)
    except ValueError:
        raise GhError("gh printed no JSON")


def refusal(branch, prs):
    """The refusal text, or None when the push may go ahead."""
    if not prs or any(p.get("state") == "OPEN" for p in prs):
        return None
    newest = max(prs, key=lambda p: p.get("number", 0))
    return (f"PRE-PUSH GUARD: {branch} has pull request #{newest.get('number')} ({newest.get('state')}) and no open one. A push here reaches "
            "nobody's review.\nSANCTIONED ROUTE: make a branch from main under a new name, bring the commits over "
            f"(`git switch -c {branch}-2 origin/main`, then `git cherry-pick`), push that branch, and open a new PR.")


def main():
    for branch in branches_pushed(sys.stdin.read().splitlines()):
        try:
            message = refusal(branch, prs_for(branch))
        except GhError as e:
            message = (f"PRE-PUSH GUARD: could not read the PR state of {branch} ({e}). The guard refuses when it cannot check.\n"
                       "SANCTIONED ROUTE: fix `gh auth status` or the network, then push again.")
        if message:
            sys.stderr.write(message + "\n")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
