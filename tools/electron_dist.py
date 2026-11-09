#!/usr/bin/env python3
"""Check or repair the Electron binary under app/node_modules/electron.

Why: on a fresh `npm install` the electron package's own installer (extract-zip 2.0.1) stopped after extracting only `dist/locales/` on Node 24.16.
The install exited 0, so nothing flagged it, and the five real-Electron specs failed 24 minutes into the full app suite (two agents hit this on 2026-11-09).
This tool is the one place that knows what a complete Electron dist is. `app/playwright.config.ts` runs `check` at config load, so a broken dist stops
a run in under a second, and the app's `postinstall` script runs `repair --soft` so a fresh worktree repairs itself.

Usage: python -I tools/electron_dist.py check|repair [--app-dir app] [--cache-dir DIR] [--soft]
  check   exit 0 when dist/electron.exe, dist/version (equal to package.json) and path.txt exist (or ELECTRON_OVERRIDE_DIST_PATH holds electron.exe).
          Otherwise prints ELECTRON_DIST_INCOMPLETE (or ELECTRON_PACKAGE_MISSING) with the repair command and exits 1.
  repair  does nothing when the dist is complete. Otherwise it finds the cached official zip, verifies its SHA-256 against the package's
          checksums.json, extracts it with Python's zipfile and writes path.txt. Names ELECTRON_ZIP_HASH_MISMATCH or ELECTRON_ZIP_NOT_CACHED and exits 1
          when it cannot. --soft prints the same message and exits 0 (for npm postinstall, which must never fail an install).
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import shutil
import sys
import zipfile


def package_dir(app_dir):
    return pathlib.Path(app_dir) / "node_modules" / "electron"


def read_version(pkg):
    try:
        return json.loads((pkg / "package.json").read_text(encoding="utf-8"))["version"]
    except (OSError, ValueError, KeyError):
        return None


def problems(pkg, version):
    """What is missing from the dist, as short phrases. Empty means complete."""
    override = os.environ.get("ELECTRON_OVERRIDE_DIST_PATH")
    if override:
        return [] if (pathlib.Path(override) / "electron.exe").is_file() else [f"ELECTRON_OVERRIDE_DIST_PATH {override} has no electron.exe"]
    found = []
    dist = pkg / "dist"
    if not (dist / "electron.exe").is_file():
        found.append("dist/electron.exe is missing")
    shipped = None
    try:
        shipped = (dist / "version").read_text(encoding="utf-8").strip().lstrip("v")
    except OSError:
        found.append("dist/version is missing")
    if shipped is not None and shipped != version:
        found.append(f"dist/version is {shipped}, package.json says {version}")
    if not (pkg / "path.txt").is_file():
        found.append("path.txt is missing")
    return found


def zip_name(version):
    arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x64"
    return f"electron-v{version}-win32-{arch}.zip"


def default_cache_dir():
    return pathlib.Path(os.environ.get("LOCALAPPDATA", "")) / "electron" / "Cache"


def find_zip(cache_dir, name):
    root = pathlib.Path(cache_dir)
    return next(root.rglob(name), None) if root.is_dir() else None


def command_hint(app_dir):
    return f"python -I tools/electron_dist.py repair --app-dir {app_dir}"


def check(app_dir):
    pkg = package_dir(app_dir)
    version = read_version(pkg)
    if version is None:
        print(f"ELECTRON_PACKAGE_MISSING: {pkg.as_posix()}/package.json is absent. Run `npm ci` in {app_dir}.")
        return 1
    found = problems(pkg, version)
    if not found:
        return 0
    print(f"ELECTRON_DIST_INCOMPLETE: {'; '.join(found)} (electron {version}). Repair it with: {command_hint(app_dir)}")
    return 1


def repair(app_dir, cache_dir, soft):
    pkg = package_dir(app_dir)
    version = read_version(pkg)
    if version is None:
        print(f"ELECTRON_PACKAGE_MISSING: {pkg.as_posix()}/package.json is absent. Run `npm ci` in {app_dir}.")
        return 0 if soft else 1
    if not problems(pkg, version):
        return 0
    if sys.platform != "win32":
        print("ELECTRON_REPAIR_SKIPPED: this tool repairs the Windows binary only.")
        return 0
    name = zip_name(version)
    cached = find_zip(cache_dir, name)
    if cached is None:
        print(f"ELECTRON_ZIP_NOT_CACHED: no {name} under {pathlib.Path(cache_dir).as_posix()}. "
              f"Run `node {pkg.as_posix()}/install.js` with network access, or copy the zip into that folder.")
        return 0 if soft else 1
    try:
        want = json.loads((pkg / "checksums.json").read_text(encoding="utf-8")).get(name, "").lower()
    except (OSError, ValueError):
        want = ""
    got = hashlib.sha256(cached.read_bytes()).hexdigest()
    if not want or got != want:
        print(f"ELECTRON_ZIP_HASH_MISMATCH: {cached.as_posix()} has SHA-256 {got}; checksums.json expects {want or 'an entry that is absent'}. "
              "Move that zip away and run the installer again.")
        return 0 if soft else 1
    dist = pkg / "dist"
    if dist.exists():
        shutil.move(str(dist), str(dist.with_name(f"dist-incomplete-{os.getpid()}")))   # kept aside, never deleted
    dist.mkdir(parents=True)
    with zipfile.ZipFile(cached) as z:
        z.extractall(dist)
    (pkg / "path.txt").write_text("electron.exe", encoding="utf-8")
    print(f"electron_dist: repaired electron {version} from {cached.as_posix()} (SHA-256 matches checksums.json)")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("action", choices=("check", "repair"))
    ap.add_argument("--app-dir", default="app")
    ap.add_argument("--cache-dir", default=str(default_cache_dir()))
    ap.add_argument("--soft", action="store_true", help="repair never fails: print the problem and exit 0")
    args = ap.parse_args(argv)
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    return check(args.app_dir) if args.action == "check" else repair(args.app_dir, args.cache_dir, args.soft)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
