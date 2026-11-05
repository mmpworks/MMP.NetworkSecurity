#!/usr/bin/env python
"""Fails when git tracks or has staged a key, a session file, or a file from .security/.

Run from a repository root with no argument. Exit 0 when clean. Exit 1 and one line per problem, each naming the path.
A sentence that only names a PEM header is no key, so the rule looks for a whole block: header, base64 body, footer.
acceptance/CONTRACT.md section 5.5 and docs/modes-design.md section 5.2 are the contract.
"""
import os
import re
import subprocess
import sys

ALLOW_LIST = {
    "src/NetSec.Core/Pki/TrainingPki.cs",
    "tests/NetSec.Tests/Tls13Tests.cs",
    "acceptance/lib/Harness/OpenSshKey.cs",
}
FORBIDDEN_PATH = re.compile(
    r"(^|/)\.security/|\.(pfx|p12|db|key|ndjson)$|(^|/)(master\.key|id_rsa|id_ed25519|known_hosts)$",
    re.IGNORECASE,
)
# The words are joined here so this file holds no header of its own.
MARKER = "PRIV" + "ATE KEY"
PEM_BLOCK = re.compile(
    "-----BEGIN [A-Z ]*" + MARKER + "-----[A-Za-z0-9+/=\\s]{16,}?-----END [A-Z ]*" + MARKER + "-----"
)
# Golden traces hold built-in training keys, which are public by design. A session file on a learner's keys is what the rule exists for.
GOLDEN_FOLDER = "acceptance/golden/"
LARGEST_SCANNED = 8 * 1024 * 1024


def git_paths(*args):
    out = subprocess.run(("git",) + args, capture_output=True, text=True, check=True).stdout
    return [line.strip().replace("\\", "/") for line in out.splitlines() if line.strip()]


def problem_with(path):
    if FORBIDDEN_PATH.search(path) and not path.startswith(GOLDEN_FOLDER):
        return path + ": a path that holds keys or session data is tracked or staged"
    if path in ALLOW_LIST or not os.path.isfile(path) or os.path.getsize(path) > LARGEST_SCANNED:
        return None
    with open(path, "rb") as f:
        text = f.read().decode("latin-1")
    return path + ": holds a PEM private key block and is not on the allow-list" if PEM_BLOCK.search(text) else None


def main():
    paths = sorted(set(git_paths("ls-files")) | set(git_paths("diff", "--cached", "--name-only", "--diff-filter=d")))
    problems = [p for p in (problem_with(path) for path in paths) if p]
    for p in problems:
        print(p)
    if subprocess.run(["git", "check-ignore", "-q", ".security/x"]).returncode != 0:
        print(".gitignore: git does not ignore .security/")
        problems.append("ignore")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
