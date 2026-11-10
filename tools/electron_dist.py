#!/usr/bin/env python3
"""Check or repair the Electron binary under app/node_modules/electron.

Why: on a fresh `npm install` the electron package's own installer (extract-zip 2.0.1) stopped after extracting only `dist/locales/` on Node 24.16.
The install exited 0, so nothing flagged it, and the five real-Electron specs failed 24 minutes into the full app suite (two agents hit this on 2026-11-09).
This tool is the one place that knows what a complete Electron dist is. `app/playwright.config.ts` runs `check` at config load, so a broken dist stops
a run in under a second, and the app's `postinstall` script runs `repair --soft` so a fresh worktree repairs itself.

Usage: python -I tools/electron_dist.py check|repair [--app-dir app] [--cache-dir DIR] [--soft] [--platform NAME]
  check   exit 0 when the dist is complete, and on any platform but win32 (the tool knows the Windows binary only). Complete means dist/version equals
          package.json, path.txt exists, and every file of the expected list exists with the expected size. The expected list comes from, in order:
          1. node_modules/electron/dist-manifest.json (written by `repair`: every zip entry and its size);
          2. the cached official zip's central directory (every entry, equal size);
          3. a fixed core list (electron.exe, ffmpeg.dll, icudtl.dat, resources.pak, v8_context_snapshot.bin, resources/default_app.asar, the
             swiftshader and vulkan files), existence only.
          ELECTRON_OVERRIDE_DIST_PATH holding electron.exe also counts. Otherwise prints ELECTRON_DIST_INCOMPLETE (or ELECTRON_PACKAGE_MISSING) with the
          repair command and exits 1.
  repair  does nothing when the dist is complete. Otherwise it finds the cached official zip IN THE LOCAL CACHE (it never downloads and never touches
          the network), verifies its SHA-256 against the package's checksums.json, parks the old dist as dist-incomplete-<timestamp>-<pid> (printed;
          about 250 MB, it goes on the removal list), extracts the zip with Python's zipfile, writes dist-manifest.json and then path.txt. Names
          ELECTRON_ZIP_HASH_MISMATCH or ELECTRON_ZIP_NOT_CACHED and exits 1 when it cannot. --soft prints the same message and exits 0 (for npm
          postinstall, which must never fail an install).
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import platform
import shutil
import sys
import zipfile


CORE_FILES = ("electron.exe", "ffmpeg.dll", "icudtl.dat", "resources.pak", "v8_context_snapshot.bin", "resources/default_app.asar",
              "vk_swiftshader.dll", "vk_swiftshader_icd.json", "vulkan-1.dll")
MANIFEST = "dist-manifest.json"
SHOWN = 8


def package_dir(app_dir):
    return pathlib.Path(app_dir) / "node_modules" / "electron"


def read_version(pkg):
    try:
        return json.loads((pkg / "package.json").read_text(encoding="utf-8"))["version"]
    except (OSError, ValueError, KeyError):
        return None


def zip_name(version):
    arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x64"
    return f"electron-v{version}-win32-{arch}.zip"


def zip_sizes(zip_path):
    """{entry name: size} for the files in a zip, read from its central directory."""
    with zipfile.ZipFile(zip_path) as z:
        return {i.filename: i.file_size for i in z.infolist() if not i.filename.endswith("/")}


def expected_files(pkg, version, cache_dir):
    """{name: size or None} the dist must hold: the manifest, else the cached zip, else the core list (size None means existence only)."""
    try:
        manifest = json.loads((pkg / MANIFEST).read_text(encoding="utf-8"))
        if manifest.get("version") == version and manifest.get("files"):
            return dict(manifest["files"])
    except (OSError, ValueError):
        pass
    cached = find_zip(cache_dir, zip_name(version))
    if cached is not None:
        try:
            return zip_sizes(cached)
        except (OSError, zipfile.BadZipFile):
            pass
    return {name: None for name in CORE_FILES}


def problems(pkg, version, cache_dir):
    """What is missing from the dist, as short phrases. Empty means complete."""
    override = os.environ.get("ELECTRON_OVERRIDE_DIST_PATH")
    if override:
        return [] if (pathlib.Path(override) / "electron.exe").is_file() else [f"ELECTRON_OVERRIDE_DIST_PATH {override} has no electron.exe"]
    found = []
    dist = pkg / "dist"
    shipped = None
    try:
        shipped = (dist / "version").read_text(encoding="utf-8").strip().lstrip("v")
    except OSError:
        found.append("dist/version is missing")
    if shipped is not None and shipped != version:
        found.append(f"dist/version is {shipped}, package.json says {version}")
    if not (pkg / "path.txt").is_file():
        found.append("path.txt is missing")
    wrong = []
    for name, size in sorted(expected_files(pkg, version, cache_dir).items()):
        target = dist / name
        if not target.is_file():
            wrong.append(f"dist/{name} is missing")
        elif size is not None and target.stat().st_size != size:
            wrong.append(f"dist/{name} is {target.stat().st_size} bytes, expected {size}")
    if len(wrong) > SHOWN:
        wrong = wrong[:SHOWN] + [f"and {len(wrong) - SHOWN} more files"]
    return wrong + found


def default_cache_dir():
    return pathlib.Path(os.environ.get("LOCALAPPDATA", "")) / "electron" / "Cache"


def find_zip(cache_dir, name):
    root = pathlib.Path(cache_dir)
    return next(root.rglob(name), None) if root.is_dir() else None


def command_hint(app_dir):
    return f"python -I tools/electron_dist.py repair --app-dir {app_dir}"


def check(app_dir, cache_dir, plat):
    if plat != "win32":
        return 0                                  # the tool knows the Windows binary only; a Mac or Linux install is the package's own business
    pkg = package_dir(app_dir)
    version = read_version(pkg)
    if version is None:
        print(f"ELECTRON_PACKAGE_MISSING: {pkg.as_posix()}/package.json is absent. Run `npm ci` in {app_dir}.")
        return 1
    found = problems(pkg, version, cache_dir)
    if not found:
        return 0
    print(f"ELECTRON_DIST_INCOMPLETE: {'; '.join(found)} (electron {version}). Repair it with: {command_hint(app_dir)}")
    return 1


def repair(app_dir, cache_dir, soft, plat):
    pkg = package_dir(app_dir)
    version = read_version(pkg)
    if version is None:
        print(f"ELECTRON_PACKAGE_MISSING: {pkg.as_posix()}/package.json is absent. Run `npm ci` in {app_dir}.")
        return 0 if soft else 1
    if not problems(pkg, version, cache_dir):
        return 0
    if plat != "win32":
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
        stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
        parked = dist.with_name(f"dist-incomplete-{stamp}-{os.getpid()}")
        shutil.move(str(dist), str(parked))      # kept aside, never deleted
        print(f"electron_dist: parked the incomplete dist at {parked.as_posix()} (about 250 MB; add it to the removal list)")
    dist.mkdir(parents=True)
    with zipfile.ZipFile(cached) as z:
        z.extractall(dist)
    (pkg / MANIFEST).write_text(json.dumps({"version": version, "zip": name, "files": zip_sizes(cached)}, indent=1), encoding="utf-8")
    (pkg / "path.txt").write_text("electron.exe", encoding="utf-8")                  # last: its presence means the extract finished
    print(f"electron_dist: repaired electron {version} from {cached.as_posix()} (SHA-256 matches checksums.json)")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("action", choices=("check", "repair"))
    ap.add_argument("--app-dir", default="app")
    ap.add_argument("--cache-dir", default=str(default_cache_dir()))
    ap.add_argument("--soft", action="store_true", help="repair never fails: print the problem and exit 0")
    ap.add_argument("--platform", default=sys.platform, help="the platform to act for (tests pass darwin); default is this one")
    args = ap.parse_args(argv)
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.action == "check":
        return check(args.app_dir, args.cache_dir, args.platform)
    return repair(args.app_dir, args.cache_dir, args.soft, args.platform)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
