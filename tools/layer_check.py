#!/usr/bin/env python
"""Fails on a dependency edge that points up the folder table in docs/program-design.md section 1.

A folder may use folders of its own row and of earlier rows. Three named exceptions come from acceptance/CONTRACT.md:
  1. Io names NetSec.Bridge.DeviceProfile, by full name only, because the contract keeps that type in Bridge.
  2. Machine/IStepGate.cs uses MMP.AsyncProxy, because the contract keeps IStepGate in Machine.
  3. Bridge, Labs and Native sit above Io and may use it. Only Io, Bridge and Labs may use MMP.AsyncProxy or System.Net.Sockets.
#if NETCF stays in Platform.

Usage: python tools/layer_check.py src/NetSec.Core
"""
import os
import re
import sys

ROWS = [
    ["Bytes", "Errors"],
    ["Crypto"],
    ["Platform"],
    ["Trace"],
    ["Keys", "Pki"],
    ["Machine"],
    ["Tls13", "Tls11", "Ssh"],
    ["Dukpt", "Auth"],
    ["Io"],
    ["Bridge"],
    ["Native"],
    ["Labs"],
]
RANK = {folder: row for row, folders in enumerate(ROWS) for folder in folders}
ASYNC_ALLOWED = {"Io", "Bridge", "Labs"}
ASYNC_ALLOWED_FILES = {"Machine/IStepGate.cs"}
USING = re.compile(r"^\s*using\s+(?P<name>[A-Za-z0-9_.]+)\s*;", re.M)
FULL_BRIDGE = re.compile(r"NetSec\.Bridge\.(?P<member>[A-Za-z0-9_]+)")
IF_NETCF = re.compile(r"^\s*#\s*(?:if|elif)\b.*\bNETCF\b", re.M)


def problems_in(rel, folder, text):
    found = []
    for match in USING.finditer(text):
        name = match.group("name")
        if name.startswith("NetSec."):
            used = name.split(".")[1]
            if used not in RANK:
                found.append("%s: using %s names no folder in the table" % (rel, name))
            elif RANK[used] > RANK[folder]:
                found.append("%s: %s (row %d) uses %s (row %d), an upward edge" % (rel, folder, RANK[folder], used, RANK[used]))
        if name.startswith("MMP.AsyncProxy") and folder not in ASYNC_ALLOWED and rel not in ASYNC_ALLOWED_FILES:
            found.append("%s: %s uses MMP.AsyncProxy; only Io, Bridge and Labs may" % (rel, folder))
        if name == "System.Net.Sockets" and folder not in ASYNC_ALLOWED:
            found.append("%s: %s uses System.Net.Sockets; only Io, Bridge and Labs may" % (rel, folder))
    if folder == "Io":
        for match in FULL_BRIDGE.finditer(text):
            if match.group("member") != "DeviceProfile":
                found.append("%s: Io names NetSec.Bridge.%s; only DeviceProfile is allowed" % (rel, match.group("member")))
    if folder != "Platform" and IF_NETCF.search(text):
        found.append("%s: #if NETCF outside Platform" % rel)
    return found


def main(root):
    problems, files = [], 0
    for folder in sorted(os.listdir(root)):
        path = os.path.join(root, folder)
        if not os.path.isdir(path) or folder in ("bin", "obj"):
            continue
        if folder not in RANK:
            problems.append("%s: this folder is not in the table in tools/layer_check.py" % folder)
            continue
        for directory, _, names in os.walk(path):
            for name in names:
                if not name.endswith(".cs"):
                    continue
                full = os.path.join(directory, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                with open(full, encoding="utf-8") as handle:
                    problems.extend(problems_in(rel, folder, handle.read()))
                files += 1
    for problem in problems:
        print("LAYER " + problem)
    print("layer_check: %d files, %d problems" % (files, len(problems)))
    return 1 if problems or files == 0 else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: layer_check.py <NetSec.Core folder>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
