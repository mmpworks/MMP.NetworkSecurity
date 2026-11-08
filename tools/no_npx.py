#!/usr/bin/env python3
"""Fail when a script this repo runs calls npx.

Why: on this machine `npx --no-install tsc` ran a different npm package named "tsc" from the cache when no local TypeScript existed
(found by Echo), so npx can execute code that is not ours. A local file (`node node_modules/<pkg>/cli.js`) or an `npm run` script resolves
local binaries and fails by name when the tool is absent.

Scans tools/, app/scripts/, app/package.json and app/*.config.* (playwright.config.ts starts the preview server for every e2e run). acceptance/ belongs to Echo's suite and is
checked there. Usage: python -I tools/no_npx.py [--root REPO]. Exit 0 clean, 1 when a call is found.
"""
import argparse
import pathlib
import re
import sys

NPX = re.compile(r"\bnpx(?:\.cmd)?\b")
SELF = {"no_npx.py", "test_no_npx.py"}
SUFFIXES = {".ps1", ".py", ".mjs", ".cjs", ".js", ".ts", ".json"}


def files(root):
    for folder in ("tools", "app/scripts"):
        base = root / folder
        if base.is_dir():
            for path in sorted(base.rglob("*")):
                if path.is_file() and path.suffix in SUFFIXES and path.name not in SELF:
                    yield path
    app = root / "app"
    if app.is_dir():
        # package.json scripts, and the config files that start servers for the e2e run (playwright.config.ts starts the preview server)
        yield from sorted(p for p in [app / "package.json", *app.glob("*.config.*")] if p.is_file())


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parent.parent))
    args = ap.parse_args(argv)
    root = pathlib.Path(args.root)
    hits = []
    for path in files(root):
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if NPX.search(line):
                hits.append(f"NPX_FOUND: {path.relative_to(root).as_posix()}:{number}: {line.strip()[:120]}")
    if hits:
        print("\n".join(hits))
        print("npx can run a package from outside this repo. Use the local file (node node_modules/<pkg>/...) or an npm run script.")
        return 1
    print("no npx in tools/, app/scripts, app/package.json or app/*.config.*")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
