#!/usr/bin/env python
"""Fails when git tracks or has staged a key, a session file, or a file from .security/.

Run from a repository root with no argument. Exit 0 when clean. Exit 1 and one line per problem, each naming the path.
It reads what the index holds, because that is what a commit takes. The working copy may differ.
A sentence that only names a PEM header is no key, so the rule looks for a whole block: header, base64 body, footer.
acceptance/CONTRACT.md section 5.5 and docs/modes-design.md section 5.2 are the contract.
"""
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
    # The body cannot cross another BEGIN, so a header named in prose cannot open a match that swallows a real key after it.
    "-----BEGIN [A-Z0-9 ]*" + MARKER + "-----(?P<body>(?:(?!-----BEGIN ).){0,65536}?)-----END [A-Z0-9 ]*" + MARKER + "-----",
    re.DOTALL,
)
# A key's body is base64, whatever wraps its lines: escapes, quotes, XML, comment marks. The smallest key here, an Ed25519 seed in PKCS#8, is 64 characters.
BASE64_RUN = re.compile(r"[A-Za-z0-9+/=]+")
SMALLEST_KEY = 64
# Golden traces hold built-in training keys, which are public by design. A session file on a learner's keys is what the rule exists for.
GOLDEN_FOLDER = "acceptance/golden/"


def index_paths():
    out = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout
    return [p.decode("utf-8", "surrogateescape").replace("\\", "/") for p in out.split(b"\0") if p]


def index_blobs(paths):
    """Yields (path, bytes or None) from the index. None means git could not give the blob."""
    names = "".join(":" + p + "\n" for p in paths).encode("utf-8", "surrogateescape")
    with subprocess.Popen(["git", "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as git:
        out, _ = git.communicate(names)
    at = 0
    for path in paths:
        end = out.index(b"\n", at)
        header = out[at:end].split(b" ")
        at = end + 1
        if len(header) != 3:
            yield path, None
            continue
        size = int(header[2])
        yield path, out[at:at + size]
        at += size + 1


def holds_key(data):
    """A UTF-16 file reads as text once its NUL bytes are gone. Latin-1 keeps every byte as one character."""
    text = data.replace(b"\0", b"").decode("latin-1")
    for match in PEM_BLOCK.finditer(text):
        if sum(len(run) for run in BASE64_RUN.findall(match.group("body"))) >= SMALLEST_KEY:
            return True
    return False


def problem_with(path, data):
    golden_trace = path.startswith(GOLDEN_FOLDER) and path.endswith(".ndjson")
    if FORBIDDEN_PATH.search(path) and not golden_trace:
        return path + ": a path that holds keys or session data is tracked or staged"
    if path in ALLOW_LIST:
        return None
    if data is None:
        return path + ": git could not read this file from the index, so the guard cannot clear it"
    return path + ": holds a PEM private key block and is not on the allow-list" if holds_key(data) else None


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    paths = index_paths()
    problems = [p for p in (problem_with(path, data) for path, data in index_blobs(paths)) if p]
    for p in problems:
        print(p)
    if subprocess.run(["git", "check-ignore", "-q", ".security/x"]).returncode != 0:
        print(".gitignore: git does not ignore .security/")
        problems.append("ignore")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
