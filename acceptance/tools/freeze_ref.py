"""Makes and checks the frozen reference for the AO checks (docs/algorithm-optimization-prd.md section 3, AO-2).

The reference is the crypto source of main at 5c5d4a4, read with `git show`. The only change is the namespace, so the reference can
compile beside the product in one program: NetSec.<X> becomes Acceptance.Frozen.<X> for Crypto, Dukpt, Tls11, Errors and Bytes.

A copy edited by hand is a new reference. So --check makes the copy again from git and fails if one byte differs.

Run: python -I freeze_ref.py --write | --check   [--repo PATH]
"""
import hashlib
import os
import subprocess
import sys

ACC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ACC, "groups", "algo", "Frozen")
COMMIT = "5c5d4a477d2dfe26cdf4cfec7eae1a0adb107dfc"

FILES = [
    "src/NetSec.Core/Crypto/Arg.cs", "src/NetSec.Core/Crypto/Endian.cs", "src/NetSec.Core/Crypto/ConstantTime.cs",
    "src/NetSec.Core/Crypto/IHash.cs", "src/NetSec.Core/Crypto/BlockHash.cs", "src/NetSec.Core/Crypto/Md5Hash.cs",
    "src/NetSec.Core/Crypto/Sha1Hash.cs", "src/NetSec.Core/Crypto/Sha256Hash.cs", "src/NetSec.Core/Crypto/Sha512Hash.cs",
    "src/NetSec.Core/Crypto/Sha3Hash.cs", "src/NetSec.Core/Crypto/Keccak.cs", "src/NetSec.Core/Crypto/Shake.cs",
    "src/NetSec.Core/Crypto/Hashes.cs", "src/NetSec.Core/Crypto/Hmac.cs", "src/NetSec.Core/Crypto/Hkdf.cs",
    "src/NetSec.Core/Crypto/AesKey.cs", "src/NetSec.Core/Crypto/AesKey.Walk.cs", "src/NetSec.Core/Crypto/Modes.cs", "src/NetSec.Core/Crypto/Gf128.cs",
    "src/NetSec.Core/Crypto/Gcm.cs", "src/NetSec.Core/Crypto/Cmac.cs", "src/NetSec.Core/Crypto/Des.cs",
    "src/NetSec.Core/Crypto/TdesKey.cs",
    "src/NetSec.Core/Tls11/Tls11Prf.cs",
    "src/NetSec.Core/Dukpt/PinBlock.cs", "src/NetSec.Core/Dukpt/DukptDerivation.cs",
    "src/NetSec.Core/Dukpt/DukptBank.cs", "src/NetSec.Core/Dukpt/DukptPinPad.cs",
    "src/NetSec.Core/Errors/Errors.cs", "src/NetSec.Core/Bytes/Bytes.cs",
]

# Every NetSec namespace the frozen files name moves under Acceptance.Frozen, so the copy needs no product DLL (the selftest group
# compiles it with none) and no frozen type can bind to a product type by accident.
NAMESPACES = ("Crypto", "Dukpt", "Tls11", "Errors", "Bytes")
REWRITES = [("namespace NetSec." + n, "namespace Acceptance.Frozen." + n) for n in NAMESPACES] + \
           [("using NetSec." + n + ";", "using Acceptance.Frozen." + n + ";") for n in NAMESPACES] + \
           [("NetSec." + n + ".", "Acceptance.Frozen." + n + ".") for n in NAMESPACES]

HEADER = "// FROZEN REFERENCE. Made by acceptance/tools/freeze_ref.py from {path} at {commit} (blob sha256 {sha}). Do not edit.\n"


def repo_root(argv):
    if "--repo" in argv:
        return argv[argv.index("--repo") + 1]
    return os.path.dirname(ACC)


def frozen_text(repo, path):
    raw = subprocess.run(["git", "-C", repo, "show", COMMIT + ":" + path], capture_output=True, check=True).stdout
    text = raw.decode("utf-8-sig")
    for old, new in REWRITES:
        text = text.replace(old, new)
    return HEADER.format(path=path, commit=COMMIT, sha=hashlib.sha256(raw).hexdigest()) + text


def out_name(path):
    return os.path.basename(path)


def main(argv):
    repo = repo_root(argv)
    wanted = {out_name(p): frozen_text(repo, p) for p in FILES}
    if "--write" in argv:
        os.makedirs(OUT, exist_ok=True)
        for name, text in wanted.items():
            with open(os.path.join(OUT, name), "w", encoding="utf-8", newline="") as f:
                f.write(text)
        print("FROZEN_WRITTEN %d files from %s" % (len(wanted), COMMIT))
        return 0
    have = sorted(f for f in os.listdir(OUT) if f.endswith(".cs")) if os.path.isdir(OUT) else []
    problems = []
    for name in sorted(set(have) | set(wanted)):
        if name not in wanted:
            problems.append("extra file " + name)
        elif name not in have:
            problems.append("missing file " + name)
        else:
            with open(os.path.join(OUT, name), encoding="utf-8", newline="") as f:
                if f.read() != wanted[name]:
                    problems.append("changed file " + name)
    if problems:
        print("FROZEN_DIFFERS: " + "; ".join(problems))
        return 1
    print("FROZEN_MATCHES %d files from %s" % (len(wanted), COMMIT))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
