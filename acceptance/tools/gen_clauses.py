"""Writes acceptance/clauses.json from the clause code, and checks it.

clauses.json is the list that fixes M: the number of clauses every report divides by. The author runs this script after adding,
renaming or removing a clause, then commits both. run.ps1 runs it with --check on every run: a clause in code that is missing from the
file, or in the file and missing from code, is a FAIL of SELF.clauses-json-matches-code.

Run: python -I gen_clauses.py [--write] [--check]
"""
import glob
import json
import os
import re
import subprocess
import sys

ACC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GROUPS = {
    "prim":       {"kind": "csharp", "project": "groups/prim/prim.csproj", "assembly": "Acceptance.Prim", "builds": ["net10", "cf"], "needsCore": True},
    "dukpt":      {"kind": "csharp", "project": "groups/dukpt/dukpt.csproj", "assembly": "Acceptance.Dukpt", "builds": ["net10", "cf"], "needsCore": True},
    "kschedule":  {"kind": "csharp", "project": "groups/kschedule/kschedule.csproj", "assembly": "Acceptance.KeySchedule", "builds": ["net10", "cf"], "needsCore": True},
    "tls13live":  {"kind": "csharp", "project": "groups/tls13live/tls13live.csproj", "assembly": "Acceptance.Tls13Live", "builds": ["net10", "cf"], "needsCore": True},
    "tls11":      {"kind": "csharp", "project": "groups/tls11/tls11.csproj", "assembly": "Acceptance.Tls11", "builds": ["net10", "cf"], "needsCore": True},
    "ssh":        {"kind": "csharp", "project": "groups/ssh/ssh.csproj", "assembly": "Acceptance.Ssh", "builds": ["net10", "cf"], "needsCore": True},
    "auth":       {"kind": "csharp", "project": "groups/auth/auth.csproj", "assembly": "Acceptance.Auth", "builds": ["net10"], "needsCore": True},
    "native":     {"kind": "csharp", "project": "groups/native/native.csproj", "assembly": "Acceptance.Native", "builds": ["net10", "cf"], "needsCore": False},
    "nativeprod": {"kind": "csharp", "project": "groups/nativeprod/nativeprod.csproj", "assembly": "Acceptance.NativeProd", "builds": ["net10", "cf"], "needsCore": True},
    "bridge":     {"kind": "csharp", "project": "groups/bridge/bridge.csproj", "assembly": "Acceptance.Bridge", "builds": ["net10"], "needsCore": True},
    "host":       {"kind": "csharp", "project": "groups/host/host.csproj", "assembly": "Acceptance.Host", "builds": ["net10"], "needsCore": False},
    "walk":       {"kind": "csharp", "project": "groups/walk/walk.csproj", "assembly": "Acceptance.Walk", "builds": ["net10", "cf"], "needsCore": True},
    "golden":     {"kind": "csharp", "project": "groups/golden/golden.csproj", "assembly": "Acceptance.Golden", "builds": ["net10", "cf"], "needsCore": True},
    "a17probe":   {"kind": "csharp", "project": "groups/a17probe/a17probe.csproj", "assembly": "Acceptance.A17Probe", "builds": ["net10"], "needsCore": True},
    "a17":        {"kind": "csharp", "project": "groups/a17/a17.csproj", "assembly": "Acceptance.A17", "builds": ["net10"], "needsCore": False},
    "keys":       {"kind": "csharp", "project": "groups/keys/keys.csproj", "assembly": "Acceptance.Keys", "builds": ["net10"], "needsCore": False},
    "binproof":   {"kind": "csharp", "project": "groups/binproof/binproof.csproj", "assembly": "Acceptance.BinProof", "builds": ["net10"], "needsCore": False},
    "docs":       {"kind": "python", "script": "checks/docs_checks.py"},
    "e2e":        {"kind": "e2e", "folder": "e2e"},
    "driver":     {"kind": "pwsh"},
    "selftest":   {"kind": "selftest", "project": "selftest/selftest.csproj", "assembly": "Acceptance.SelfTest", "builds": ["net10"], "needsCore": False},
}

ASSERTIONS = {
    "A1": "AES (ECB, CBC, CTR, GCM), SHA-1, SHA-256, SHA-384, SHA-512, SHA-3, SHAKE, MD5, HMAC, CMAC, HKDF, X25519, Ed25519, RSA, TDES and DH group 14 pass published vectors on both builds",
    "A2": "10,000 random inputs for AES, HMAC, HKDF and GCM match the .NET 10 BCL; 200 ML-KEM-768 rounds interoperate with .NET 10 MLKem in both directions; RSA PKCS#1 v1.5 signatures and encryption interoperate with the .NET library on keys it made",
    "A3": "AES DUKPT matches the X9.24-3-2017 vectors for AES-128 and AES-256 base keys; pad and bank agree for 1,000 sales; used keys are absent from PIN-pad state; the tour states that a managed heap can keep copies",
    "A4": "Key schedule secrets match the RFC 8448 trace byte for byte",
    "A5": "The glass client completes TLS 1.3 against OpenSSL 3.5.7 and Go crypto/tls, with X25519 and with X25519MLKEM768; the glass server does the same if built; the referee reports the group",
    "A6": "The key log from our client equals the OpenSSL server key log for the same session",
    "A7": "Glass client completes TLS 1.1 against OpenSSL for a named RSA key transport suite and a named ECDHE CBC suite; alert 70 from a modern server beside a passing control; a TLS 1.3 client detects the DOWNGRD sentinel",
    "A8": "Glass SSH client runs one exec and one tunnel against a Go x/crypto/ssh server on the modern and legacy suites; a changed host key gives a named error beside a passing control; ssh.exe works against our server if built",
    "A9": "The shared code compiles against the CF 3.5 references with LangVersion 3; each CF binary references the CF mscorlib token; the same suite passes with CF binaries on net48 with pinned skips; git tracks no CF binary",
    "A10": "End to end: PIN pad, CE (CF binaries), gateway, server and bank HSM as separate processes; a locked PIN block travels SSH then TLS 1.3 hybrid and the bank recovers it; a tamper at each hop gives a named error beside a passing control; no DUKPT key or clear PIN in CE and gateway traces",
    "A10a": "A Go TCP tap on each hop records bytes; tap bytes equal trace bytes; randoms differ across two runs",
    "A11": "Mutual TLS, tokens, DPoP replay and role checks each have a passing control and an attack that differs by one field and gets a named rejection; our token verifies under a Go verifier",
    "A12": "The C++ library builds with cl.exe and loads from .NET 10 and from the net48 run; the timing lab takes 100,000 samples per case and the leaky compare separates from constant time by a stated Welch t threshold",
    "A13": "The Electron app renderer starts from a fresh clone beside sibling MMP.AsyncProxy and the CF references; Playwright walks every step of every built lesson against a live Host; screenshots are saved",
    "A14": "Every tour step binds to a live trace event or is marked as a concept step; at most 30 percent concept steps per lesson; a test fails on a dangling binding",
    "A15": "All tour text scores Flesch-Kincaid grade 8.9 or lower by script and passes tic-gate.py",
    "A15a": "Each security claim in a tour cites a source section, and an agent that did not write it reads it for accuracy",
    "A16": "A real IKeyHandle given to the glass-box factory fails by type; the OS transport runs SslStream and its output holds no secret bytes; the UI labels the glass-box engine TRAINING ONLY; the CE wording is used",
    "A17": "Per-type Mock or My test key modes: the readiness rule refuses by name, the five wizards are driven by a machine that owns the moves, the vault keeps keys and an audit chain, Show keys hides values, and every claim of proof names an outside referee or says known-answer",
    "A19": "The AES walk shows every state of one block, encrypt and decrypt, from the real engine: states, key rows and tables equal FIPS 197, a live run equals an independent AES and the BCL, Show keys OFF closes the states, and the app holds no table",
    "A18": "Each lesson says on screen what its engine leaves out, by the gaps of docs/conformance-matrix.md; a real peer shows each named refusal beside a control that connects",
    "SELF": "Harness self-check: the suite bites",
}

# Owning slice per prd.md "Acceptance assertions" and the S-table of program-design.md section 8. A1 splits by primitive.
S4_PRIMITIVES = ("A1.md5", "A1.sha1", "A1.hmac-md5", "A1.hmac-sha1", "A1.hkdf-sha1", "A1.rsa", "A1.tdes", "A1.dh-group14")
SLICE = {"A2": "S1", "A3": "S2", "A4": "S3", "A5": "S3", "A6": "S3", "A7": "S4", "A8": "S4", "A9": "All", "A10": "S5", "A10a": "S5",
         "A11": "S6", "A12": "S7", "A13": "Each", "A14": "Each", "A15": "Each", "A15a": "Each", "A16": "S8", "A17": "V0", "A18": "Each", "A19": "W1", "SELF": "S0"}

# Clauses whose slice differs from their assertion's default. The A17 certificate clauses test V4, certificate import (docs/modes-design.md, the
# V4 row of the clause table), not V0 (#333).
SLICE_BY_ID = {cid: "V4" for cid in ("A17.attacks.hit-named-field", "A17.attacks.unavailable-names-code", "A17.chain.alg-unsupported-named",
                                      "A17.clock.new-certificate-not-expired", "A17.proof.root-negative-control")}

REFEREE = {"A1": "published vectors", "A2": ".NET 10 BCL oracle", "A3": "x9.org vectors", "A4": "RFC 8448", "A5": "OpenSSL 3.5.7 and Go crypto/tls", "A6": "OpenSSL 3.5.7",
           "A7": "OpenSSL 3.5.7", "A8": "Go x/crypto/ssh and ssh.exe", "A9": "CF references and System.Reflection.Metadata", "A10": "live run, Go referees and taps",
           "A10a": "Go tap", "A11": "Go tokenverify", "A12": "cl.exe and a live run", "A13": "Playwright", "A14": "test over the tour files and a live Host",
           "A18": "script over the tour files; OpenSSL 3.5.7 and Go referees for refusals", "A19": "FIPS 197 (2001) data, the suite's RefAes, and the .NET library", "A15": "script", "A15a": "accuracy reader", "A16": "test, Playwright, OpenSSL key log", "A17": "test over HTTP and WebSocket, OpenSSL, ssh.exe, Go referees; known-answer where no outside referee exists", "SELF": "stand-ins built on the BCL, python cryptography and real OpenSSL runs"}

# A19 started as the AES walk, so its default referee names FIPS 197. The later walks have referees of their own; the first prefix that
# matches a clause id wins over the assertion's default (Jared, #281: the report's Referee column was wrong for these).
REFEREE_BY_PREFIX = [
    ("A19.host.dh-", "BigInteger.ModPow, and RFC 3526's group 14 in the vector file"),
    ("A19.host.x25519-", "RFC 7748 section 6.1 in the vector file, clamped by section 5"),
    ("A19.host.ed25519-", "RFC 8032 section 7.1 in the vector file, .NET SHA-512 and BigInteger"),
    ("A19.host.toy-curve-", "the suite's own brute force over GF(17)"),
    ("A19.host.real-curve-", "the curve and line algebra, to 1e-9"),
    ("A19.host.tls13-", "RFC 8448 section 3 in the vector file"),
    ("A19.host.tls11-", "OpenSSL pkeyutl, and the suite's TLS 1.1 PRF on .NET MD5 and SHA-1"),
    ("A19.host.sha256-", "FIPS 180-4 run in the suite (constants derived from prime roots), and .NET SHA-256"),
    ("A19.host.hmac-", "RFC 4231 in the vector file, RFC 2104 run on .NET SHA-256, and .NET HMACSHA256"),
    ("A19.host.seal-chain-", "the suite's own composition of each row's text, and .NET SHA-256"),
    ("A19.host.ecdsa-", "RFC 6979 A.2.5 in the vector file, the suite's P-256 arithmetic on .NET's curve, .NET ECDsa and OpenSSL"),
    ("A19.host.des-", "NIST CAVP in the vector file, and .NET DES (vartext: CAVP alone, weak key)"),
    ("A19.repo.", "script over the repository files"),
    ("A19.ui.dh-", "Playwright, against the Host's reply"),
    ("A19.ui.toy-curve-", "Playwright, against the Host's reply"),
    ("A19.ui.real-curve-", "Playwright, against the Host's reply"),
    ("A19.ui.x25519-", "Playwright, against the Host's reply and RFC 7748 in the vector file"),
    ("A19.ui.attack-", "the live Host's /api/lessons (lessons 0 to 11) and app/src/attacks.json, read through Playwright"),
    ("A19.ui.two-run-", "the live Host's registry and its forked runs, read through Playwright"),
    ("A19.ui.tls13-", "Playwright, against the Host's reply and RFC 8448 in the vector file"),
    ("A19.ui.tls11-", "Playwright, against the Host's reply"),
    ("A19.ui.long-strip-", "Playwright, against the Host's /api/walk/aes/long-text reply"),
    ("A19.app.", "script over the app source and copy files"),
    # The A19.walk. family is the AES walk's core reference clauses, and only those. A non-AES walk clause takes another id and its own row.
    ("A19.walk.", REFEREE["A19"]),
]

# The AES walk's Host and screen clauses, whose referee is A19's AES default. They have no common prefix, so they are named one by one.
# An A19 clause that is in neither list stops the generator: a new walk names its own referee (Jared, #295), and a clause never inherits
# the AES one by accident.
AES_WALK_IDS = {
    "A19.host.block-real-run-two-seeds", "A19.host.block-terms-real-run", "A19.host.control-run-says-not-sent", "A19.host.ecb-fork-says-match",
    "A19.host.errors-carry-a-code", "A19.host.off-holds-no-word-or-term", "A19.host.practice-key-192-256", "A19.host.rcon-steps",
    "A19.host.replies-carry-no-store", "A19.host.show-keys-off-closes-block-first", "A19.host.tables-carry-maps-rcon-sizes",
    "A19.host.tables-equal-fips-and-stay-open", "A19.host.typed-routes-follow-key-size", "A19.host.typed-routes-open-with-keys-off",
    "A19.host.walk-adds-no-trace-event",
    "A19.ui.end-frames-on-all-key-sizes", "A19.ui.expanded-table-layout", "A19.ui.first-view-fills-by-column", "A19.ui.flip-clears-with-the-frame-dropped",
    "A19.ui.flip-during-play-stops-the-timeline", "A19.ui.grid-order-on-every-state", "A19.ui.key-band-on-192-and-256", "A19.ui.late-reply-is-dropped",
    "A19.ui.multiply-shows-the-engine-terms", "A19.ui.next-alone-gives-the-text-back", "A19.ui.off-shows-the-closed-line",
    "A19.ui.play-stops-at-the-end-of-a-round", "A19.ui.reconnect-reads-the-toggle-first", "A19.ui.reduced-motion-has-no-transition",
    "A19.ui.sbox-click-matches-next-state", "A19.ui.socket-close-clears-the-walk", "A19.ui.step-order-by-next", "A19.ui.word-build-lights-its-two-words",
    # Steve's AES walk fixes, 2026-11-08: cell index and letter, the key word build in steps with role colors, Key Schedule zoom, the landscape panel.
    "A19.ui.block-cell-shows-index-and-char", "A19.ui.key-word-build-runs-in-steps", "A19.ui.key-roles-have-colors", "A19.ui.key-schedule-zoom",
    "A19.ui.key-panel-landscape-layout", "A19.ui.key-panel-xor-rcon-replay", "A19.ui.key-table-scrolls-in-its-own-box",
    # Steve's block-walk items, 2026-11-08: the MixColumns matrix panel, the AddRoundKey round-key grid, the bit lines.
    "A19.ui.mix-matrix-pairs-and-line", "A19.ui.mix-fill-all", "A19.ui.add-round-key-grid", "A19.ui.bit-lines-for-picked-byte",
    "A19.ui.inv-mix-line-matches-field-multiply",
}


def referee_of(cid, assertion):
    for prefix, referee in REFEREE_BY_PREFIX:
        if cid.startswith(prefix):
            return referee
    if assertion == "A19":
        if cid in AES_WALK_IDS:
            return REFEREE["A19"]
        sys.exit("clause %s: an A19 clause needs its referee, as a REFEREE_BY_PREFIX row or an AES_WALK_IDS entry, in gen_clauses.py" % cid)
    return REFEREE[assertion]


# A role is a part of the build that the PRD lets the team cut. A cut role makes these clauses NOT RUN, named (roles.json).
def roles_of(cid):
    r = []
    if re.match(r"A5\.server\.", cid):
        r.append("tls13.server")
    if cid == "A8.ssh.exe-to-glass-server":
        r.append("ssh.server")
    if cid == "A11.passkey.challenge-replay-beside-control":
        r.append("auth.passkey")
    if cid == "A11.roles.capability-not-granted-beside-control":
        r.append("auth.capabilities")
    if cid in ("A10.run.glass-hops", "A10.run.ssh-exe-forward", "A10.tamper.hop1-ssh-packet-mac", "A10.tamper.hop2-tls13-aead-tag",
               "A10.tamper.envelope-dukpt-mac-mismatch", "A10.privacy.no-dukpt-secrets-in-ce-and-gateway-traces",
               "A10a.tap-equals-trace.hop1", "A10a.tap-equals-trace.hop2", "A10a.randoms-differ"):
        r += ["ssh.server", "tls13.server"]
    return sorted(set(r))


def scan_csharp():
    found = []
    pat = re.compile(r'\[Clause\("(?P<id>[^"]+)"(?P<opts>[^\]]*)\)\]')
    for name, g in GROUPS.items():
        if g["kind"] not in ("csharp", "selftest"):
            continue
        folder = os.path.dirname(os.path.join(ACC, g["project"]))
        for cs in sorted(glob.glob(os.path.join(folder, "*.cs"))):
            for m in pat.finditer(open(cs, encoding="utf-8").read()):
                found.append((name, m.group("id"), "PerBuild = true" in m.group("opts")))
    return found


def scan_python():
    out = subprocess.run([sys.executable, "-I", os.path.join(ACC, "checks", "docs_checks.py"), "--root", ACC, "--list"], capture_output=True, text=True, check=True).stdout
    return [("docs", line.strip(), False) for line in out.splitlines() if line.strip()]


def scan_e2e():
    found = []
    for spec in sorted(glob.glob(os.path.join(ACC, "e2e", "*.spec.ts"))):
        text = open(spec, encoding="utf-8").read()
        for m in re.finditer(r"test\(\s*[`'\"]\[(?P<id>[^\]`'\"]+)\]", text):
            cid = m.group("id")
            if "${n}" in cid:
                for n in range(1, 12):
                    found.append(("e2e", cid.replace("${n}", str(n)), False))
            else:
                found.append(("e2e", cid, False))
    return found


DRIVER = [("driver", "A13.fresh-clone.acceptance-unchanged", False), ("driver", "A13.fresh-clone.sibling-layout", False),
          ("driver", "SELF.clauses-json-matches-code", False), ("driver", "SELF.vectors-python", False),
          ("driver", "SELF.tool-cannot-start-still-reports", False),
          ("driver", "SELF.summary-m-stays-a-count", False)]


def build():
    rows = []
    for group, cid, per_build in scan_csharp() + scan_python() + scan_e2e() + DRIVER:
        builds = GROUPS[group].get("builds", ["net10"]) if per_build else [None]
        for b in builds:
            full = cid + "." + b if b else cid
            assertion = cid.split(".")[0]
            if assertion not in ASSERTIONS:
                sys.exit("clause %s: no assertion %s in ASSERTIONS" % (cid, assertion))
            slice_ = "S4" if cid.startswith(S4_PRIMITIVES) else SLICE.get(assertion, "S1")
            if assertion == "A1" and slice_ == "S1" and not cid.startswith(S4_PRIMITIVES):
                slice_ = "S1"
            if assertion == "A16" and (cid.startswith("A16.type") or cid.startswith("A16.host")):
                slice_ = "S2" if cid.startswith("A16.type") else "S8"
            slice_ = SLICE_BY_ID.get(cid, slice_)
            rows.append({
                "id": full, "base": cid, "assertion": assertion, "group": group, "build": b or "host",
                "slice": slice_, "referee": referee_of(cid, assertion), "roles": roles_of(cid), "counts": assertion != "SELF",
            })
    rows.sort(key=lambda r: (r["assertion"] == "SELF", r["id"]))
    ids = [r["id"] for r in rows]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        sys.exit("duplicate clause ids: " + ", ".join(dup))
    return rows


def core_use_problems():
    """
    A group whose code says `using NetSec.<x>` needs the product DLL on its compile line. If needsCore is false for such a group,
    the compiler cannot find NetSec and run.ps1 would read the error as a missing product (NOT RUN PRODUCT_MISSING) while the
    product is present. This check names the group, so the mistake fails here and not as a false "product missing".
    """
    problems = []
    pat = re.compile(r"^\s*using\s+NetSec\.", re.M)
    for name, g in GROUPS.items():
        if g.get("kind") not in ("csharp", "selftest") or g.get("needsCore"):
            continue
        gdir = os.path.dirname(os.path.join(ACC, g["project"]))
        files = [os.path.join(dp, f) for dp, dn, fn in os.walk(gdir) for f in fn if f.endswith(".cs") and os.sep + "obj" + os.sep not in dp + os.sep and os.sep + "bin" + os.sep not in dp + os.sep]
        proj = open(os.path.join(ACC, g["project"]), encoding="utf-8").read()
        if "lib" in proj and "Live" in proj:
            live = os.path.join(ACC, "lib", "Live")
            files += [os.path.join(live, f) for f in os.listdir(live) if f.endswith(".cs")]
        for f in files:
            if pat.search(open(f, encoding="utf-8", errors="replace").read()):
                problems.append("%s: needsCore is false but %s uses NetSec" % (name, os.path.relpath(f, ACC)))
                break
    return problems


def main():
    mode_write = "--write" in sys.argv
    bad = core_use_problems()
    if bad:
        print("; ".join(bad))
        return 1
    rows = build()
    doc = {
        "schema": 1,
        "note": "M is the number of entries with counts true. Generated by tools/gen_clauses.py from the clause code. Do not edit by hand.",
        "assertions": ASSERTIONS,
        "groups": GROUPS,
        "clauses": rows,
    }
    path = os.path.join(ACC, "clauses.json")
    text = json.dumps(doc, indent=1) + "\n"
    if mode_write:
        open(path, "w", encoding="utf-8", newline="\n").write(text)
        print("wrote clauses.json: M = %d product clauses, %d self-checks" % (sum(1 for r in rows if r["counts"]), sum(1 for r in rows if not r["counts"])))
        return 0
    if not os.path.exists(path):
        print("clauses.json missing")
        return 1
    old = json.load(open(path, encoding="utf-8"))
    old_ids = {r["id"] for r in old["clauses"]}
    new_ids = {r["id"] for r in rows}
    if old_ids != new_ids or old["clauses"] != rows:
        only_code = sorted(new_ids - old_ids)
        only_file = sorted(old_ids - new_ids)
        print("clauses.json differs from the code. In code only: %s. In file only: %s. Run gen_clauses.py --write." % (only_code[:5], only_file[:5]))
        return 1
    print("clauses.json matches the code: %d clauses" % len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
