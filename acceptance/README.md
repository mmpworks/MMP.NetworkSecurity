# MMP.NetworkSecurity acceptance suite

Author: Echo. Date: 2026-11-05. Branch: `test/acceptance-suite`. Rule: D11. Builders never write under `acceptance/`.

Conclusion: the suite has **M = 260 product clauses** (`clauses.json`): the 208 of the first release and 52 for A17 (section 8). With no product built it reports **0 of 260 PASS, 0 FAIL, 260 NOT RUN**.
Its 31 checks on itself all PASS. The suite is written against `docs/program-design.md` section 11, `docs/modes-design.md`, and the merged referees in `acceptance/referees`. Every group compiles against the contract stub on net10.0 and on net48 with the CF build of MMP.AsyncProxy.
Disposition: merge this branch. Send the open items in section 7 and in `CONTRACT.md` section 5.7 to Richard and Jared.

## 1. Run it

```
pwsh acceptance/run.ps1 -Clauses All                 # build what exists, run, write docs/_runs/acceptance-<timestamp>.json and .md
pwsh acceptance/run.ps1 -Clauses A1,A2               # ids, assertions, slices (S3), groups (tls13live) or prefixes (A5.client)
pwsh acceptance/run.ps1 -Clauses All -Fresh          # clone HEAD beside MMP.AsyncProxy, run the clone's own script, diff acceptance/ against PIN
pwsh acceptance/run.ps1 -Contract                    # compile every group against the contract stub; run nothing
pwsh acceptance/run.ps1 -Clauses All -SelfTest       # add the checks the suite runs on itself (not part of M)
pwsh acceptance/run.ps1 -Clauses A17.mock -RecordGolden # record the golden traces into acceptance/golden/ (section 8)
```

Set `AsyncProxyRoot` (parameter or environment variable) when the clone does not sit beside `MMP.AsyncProxy`. CF references: `E:\dev\tools\netcf35-ref`, never committed.
Every clause ends PASS, FAIL or NOT RUN with a reason. The report line is `N of M clauses PASS`, and M comes from `clauses.json`.
Exit code 0 means every selected clause passed. Anything else exits 1.

## 2. Output of the run with no product

Command: `pwsh acceptance/run.ps1 -Clauses All -SelfTest` on this branch. Nothing under `src/` exists yet.

```
[acceptance] 208 clauses selected of M = 208 (+ 22 self-checks in the file)
[acceptance] group prim (net10): 32 clauses
  ... (one line for each group and build: dukpt, kschedule, tls13live, tls11, ssh, auth, nativeprod, native, bridge, host, keys, binproof, selftest, docs, e2e)
[acceptance] 0 of 208 clauses PASS (0 FAIL, 208 NOT RUN); M = 208
[acceptance] self-checks: 22 of 22 PASS
```

| Assertion | M | PASS | FAIL | NOT RUN | Slice | Referee |
|---|---|---|---|---|---|---|
| A1 | 52 | 0 | 0 | 52 | S1, S4 | published vectors |
| A2 | 12 | 0 | 0 | 12 | S1 | .NET 10 BCL oracle |
| A3 | 15 | 0 | 0 | 15 | S2 | x9.org vectors |
| A4 | 20 | 0 | 0 | 20 | S3 | RFC 8448 |
| A5 | 20 | 0 | 0 | 20 | S3 | OpenSSL 3.5.7 and Go crypto/tls |
| A6 | 4 | 0 | 0 | 4 | S3 | OpenSSL 3.5.7 |
| A7 | 12 | 0 | 0 | 12 | S4 | OpenSSL 3.5.7 |
| A8 | 12 | 0 | 0 | 12 | S4 | Go x/crypto/ssh and ssh.exe |
| A9 | 4 | 0 | 0 | 4 | All | CF references and System.Reflection.Metadata |
| A10 | 7 | 0 | 0 | 7 | S5 | live run, Go referees and taps |
| A10a | 3 | 0 | 0 | 3 | S5 | Go tap |
| A11 | 9 | 0 | 0 | 9 | S6 | Go tokenverify and Go tlspeer |
| A12 | 8 | 0 | 0 | 8 | S7 | cl.exe and a live run |
| A13 | 15 | 0 | 0 | 15 | Each | Playwright |
| A14 | 2 | 0 | 0 | 2 | Each | test over the tour files and a live Host |
| A15 | 2 | 0 | 0 | 2 | Each | script |
| A15a | 3 | 0 | 0 | 3 | Each | accuracy reader |
| A16 | 8 | 0 | 0 | 8 | S2, S8 | test, Playwright, OpenSSL key log |

| Status and reason | Clauses |
|---|---|
| NOT RUN PRODUCT_MISSING | 207 |
| NOT RUN NOT_A_FRESH_RUN (`A13.fresh-clone.acceptance-unchanged`, needs `-Fresh`) | 1 |

Self-checks (full text in the report): 22 of 22 PASS.

| Self-check | What it proves |
|---|---|
| `SELF.reference-passes` | The real A1 clause bodies pass on a BCL stand-in for 21 primitives. The vectors and the checking code agree with a second implementation |
| `SELF.every-primitive-clause-bites` | Each of those 21 clauses FAILs when one output bit flips |
| `SELF.wrong-aes-vector-fails`, `SELF.wrong-hash-vector-fails`, `SELF.wrong-implementation-fails` | A deliberately wrong AES vector, a wrong MD5 vector and a wrong AES stand-in each report FAIL, and the control beside each reports PASS |
| `SELF.dukpt-vectors-pass`, `SELF.kschedule-rfc8448-pass` | The X9.24-3 vectors (85 + 85 + 85 + 72 + 27) and the RFC 8448 trace pass on references written for the self-test |
| `SELF.vectors-python` | X25519, Ed25519, TDES (500), RSA and DH group 14 vectors pass in python `cryptography` |
| `SELF.absent-product-is-not-run`, `SELF.zero-checks-is-not-pass` | A missing type maps to NOT RUN PRODUCT_MISSING. A clause that ran zero checks is NOT RUN. Any other exception is FAIL |
| `SELF.type-clause-bites` | The A16 type clause PASSes on a faithful stub and FAILs when the glass factory accepts any object |
| `SELF.text-checks-bite` | On an empty tree every text clause is NOT RUN. A good tour passes. A bad tour fails the concept cap, the reading grade, the heap statement and tic-gate |
| `SELF.openssl-referee-smoke`, `SELF.openssh-key-format`, `SELF.wire-parsers`, `SELF.binproof-detector` | The process control and the parsers read real OpenSSL, ssh.exe, the Go `tap` and CF binaries: group, protocol, key log, SSH clear packets, TLS hellos, tap log with and without a flip, CF mscorlib token |
| `SELF.referee-protocols` | The harness speaks the real referee programs: the BCL oracle JSON lines (including an unknown algorithm), `tokenverify` result events, and the `tlspeer` port line and handshake event |
| `SELF.vector-provenance`, `SELF.clauses-json-matches-code` | Every vector group names its source. `clauses.json` equals the clause code |

Other proofs I ran by hand and do not keep in the repo:
1. A BCL-backed reference product (net10.0) with the A1 and A2 shapes, run through `run.ps1`: 21 of the 26 net10.0 A1 clauses PASS, and the four A2 primitive clauses PASS with 10,000 rounds each through a BCL oracle. The other clauses are NOT RUN because the reference lacks them (PRODUCT_MISSING). This run found one bug in the oracle reader (fixed).
2. A fake native library with the C ABI of `program-design.md` section 7: `A12.native.*` and the timing clause PASS on net10.0 and net48. Leaky \|t\| ran from 800 to 4,400 and constant-time \|t\| from 20 to 90 (cropped), so the 3 x rule holds with room.

## 3. How M is built

M is the length of `clauses.json` where `counts` is true. `tools/gen_clauses.py --write` makes the file from the clause code. `SELF.clauses-json-matches-code` fails when they differ.

| Rule | Example |
|---|---|
| A1 is one clause per primitive per build. Ids end `.net10` or `.cf` | `A1.sha256.net10`, `A1.sha256.cf` |
| A2 is one clause per primitive per build, plus both ML-KEM directions | `A2.mlkem768.ours-encaps-bcl-decaps.cf` |
| A3 is one clause per vector family, usage set, PIN block, the 1,000 sales and the erasure check, per build | `A3.vec.aes256-from-aes256.cf` |
| A4 is one clause per RFC 8448 secret group, per build | `A4.rfc8448.application-traffic-secrets.net10` |
| A5 is one clause per role, referee and group | `A5.client.openssl.x25519mlkem768.net10`, `A5.server.go.x25519.cf` |
| A7 to A9 name the attack and the control in one id | `A7.alert70.modern-server-beside-legacy-control.cf` |
| A10 is one clause for each topology, each tamper, the privacy scan | `A10.tamper.hop2-tls13-aead-tag` |
| A13 is one clause for each of the 11 lessons | `A13.walk.lesson-6` |

A cut role is listed in `roles.json`. Its clauses report NOT RUN `ROLE_CUT:<role>` by name. Roles: `auth.passkey`, `auth.capabilities`, `tls13.server`, `ssh.server`. All are `required` now.

## 4. How each assertion is anchored

| Assertion | Hardening in the clause |
|---|---|
| A1 | Published vectors only (`vectors/SOURCES.md`). Hashes run one-shot and in 1, 7, 64 and 65 byte pieces. GCM has tamper cases and the NIST FAIL records. Ed25519 has flipped-signature and altered-message controls. DH refuses a peer value of 0, 1 or p-1 |
| A2 | The BCL oracle runs in a separate process. 10,000 seeded inputs per primitive. The seed makes a failing round repeatable |
| A3 | X9 vectors are fetched at run time and cross-checked by recomputation. PIN block decrypt under another PAN must not return the PIN. The erasure check searches every register for every earlier working key |
| A4 | RFC 8448 values through `Tls13KeySchedule.Derive` (section 11). Keys, IVs and Finished keys come from the secrets `Derive` returned. The resumption secrets need `Tls13KeySchedule.Resume` (ASSUMED, asked of Richard). Until it exists, `A4.rfc8448.exporter-and-resumption` is NOT RUN DERIVE_LACKS_RESUMPTION. The engine route is not usable: the glass client sends its own ClientHello, so its transcript differs |
| A5, A6 | The group is the referee's word (`Peer Temp Key`, the Go `handshake` event). The certificates come from `TrainingPki.Export`, and `openssl verify` checks the leaf (wrong name and rogue-certificate controls). A6 compares the four labels that Go and OpenSSL both write, for the client random in `ProbeResult.KeyLog` |
| A7 | Alert 70 only counts beside a control: the same client passes against the TLS 1.1 server, and `ProbeResult.AlertReceived` is 70 for the TLS 1.3-only server. The sentinel needs `OfferOnlyTls11`, a failed `TLS13_DOWNGRADE_SENTINEL`, and `DOWNGRD 00` in the server random, read from the `tap` log. The control run offers TLS 1.3 |
| A8 | The referee prints the negotiated algorithms. The known_hosts line comes from `ssh-keygen -y` on the exported key file. The rogue host key comes from `ssh-keygen`. A changed host key gives `SSH_HOST_KEY_CHANGED` beside a control. ssh.exe uses the exported OpenSSH key file (it rejects PKCS#8 for Ed25519) |
| A9 | `System.Reflection.Metadata` reads the mscorlib token. A control shows the net10.0 build lacks the CF token, and the detector flags a planted CF binary and a copy of a CF reference. `skiplist.json` pins skips, each with a reason, and the clause also compares the net10.0 and net48 test sets |
| A10, A10a | Run from outside: processes with `READY port=` and `RESULT`, two `tap` relays, `CE-READY` required. `wire.sent` events, joined by direction, equal the tap log bytes. The privacy scan needs a positive control: the bank trace must show the PIN key it derived, and the CE trace must show hop keys |
| A11 | Each attack row runs beside its control, differs by one field, and matches `ExpectCode` and `ExpectCheck`. A token goes to the Go verifier `TOKEN_OK`, with a one-character change and an attacker-signed token as controls (`TOKEN_BAD_SIGNATURE`) |
| A12 | The suite builds `native/netsec_ct.c` itself (C++ and C, `/W4 /WX`), P/Invokes it, and computes Welch t with a common 99th percentile crop. Threshold: leaky \|t\| > 4.5 and above 3 x constant-time \|t\| |
| A13 | A fresh clone beside the sibling. The walk compares the step ids shown with the tour file. `acceptance/` is diffed against `PIN` |
| A14, A15, A15a | The grade script and the concept cap are the suite's own. Dangling bindings are tested against a live Host. Accuracy rules 1 to 8 must appear in the named lessons. Reader verdicts must come from a reader who did not write the tour |
| A16 | Compile-time negative tests against the built `NetSec.Core.dll` (control compiles, four attacks fail with named compiler errors). The OS transport is scanned for the secrets that an OpenSSL peer logs |

## 5. Routine calls I made (Steve is asleep)

| # | Call | Reason |
|---|---|---|
| 1 | Namespace rule `NetSec.<Folder>` and the ASSUMED members in `CONTRACT.md` | The design gives no namespace and leaves about 50 members open. The suite must compile against something |
| 2 | Contract stub plus `-Contract` mode | Proves the suite compiles against the signatures before any product exists |
| 3 | A clause that passes while `src/NetSec.Core` is absent is FAIL `SUITE_BUG_VACUOUS_PASS` | Keeps "no product, no PASS" true by test and not by hope |
| 4 | Ids end `.net10` or `.cf`, one clause per build | The PRD says "on both builds" |
| 5 | A4 runs on `Tls13KeySchedule.Derive` and not through the engine | RFC 8448's ClientHello differs from ours |
| 6 | X9.24-3 vectors are made at run time and stay out of git | Licence checklist item 1. Dave decides if they may ever be committed |
| 7 | SP 800-38A F.2.5 (CBC-AES256) left out | The PDF text scrambles that block. CBC with 128 and 192 bit keys, and AES-256 in ECB, CTR, GCM and FIPS 197, cover the core |
| 8 | RSA and DH group 14 known answers come from OpenSSL 3.5.7, with python cross-checks | No free published RSA PKCS#1 vector set was at hand. The PRD names OpenSSL a referee |
| 9 | TDES single-key CAVP files use one DES key three times. I added the 2-key and 3-key multi-block files | The KAT set alone would not test the EDE chain |
| 10 | Section 11 gives the process command lines. Where it is silent, `CONTRACT.md` marks the flag ASSUMED: `--seed` on a node, `--tamper-envelope`, the PIN pad result fields, `NETSEC_OS_PEER`, `mode: step` then `session.run` | The design leaves these open and A10 needs them |
| 11 | Ed25519 SSH keys are written as OpenSSH private key files | ssh.exe 9.5 rejects PKCS#8 |
| 12 | Welch t uses a common 99th percentile crop | Raw t is dominated by scheduler outliers. Uncropped t is printed beside it |
| 13 | `-Fresh` clones `HEAD` and runs the clone's own `run.ps1` | The third agent must run the code under review, not the code that launches it |
| 14 | `PIN` holds the commit of the last sanctioned `acceptance/` state, and the diff skips `PIN` itself | A commit cannot name itself |
| 15 | `A15a` reads `claims [{text, source}]` at the top of each tour file (section 11), and also from a step, and verdict files by lesson | Section 11 names the shape, not the place |
| 16 | `skiplist.json` is empty | No skip is justified yet |

## 6. NOT RUN reasons that are not PRODUCT_MISSING

In the run above: `NOT_A_FRESH_RUN` for `A13.fresh-clone.acceptance-unchanged` (1 clause).
These appear later by design, each named in the report: `REFEREE_MISSING`, `REFEREE_VERSION`, `REFEREE_PROTOCOL`, `ROLE_CUT:<role>`, `LESSON_NOT_BUILT`,
`ACCURACY_READER_PENDING`, `NO_CLAIMS_DECLARED`, `UI_CONTROL_MISSING`, `VECTORS_MISSING`, `SIBLING_MISSING`, `TOOL_MISSING`, `PIN_UNSET`.

## 7. Open items

1. **Referees.** Jared's `acceptance/referees/go` and `bcl` are merged. The suite reads their JSON events, the first-line port, the tap log format and the BCL oracle protocol from `acceptance/referees/README.md`. `SELF.referee-protocols` runs the real programs. The old `referee-contract.md` is deleted.
2. **Contract.** `CONTRACT.md` lists the ASSUMED members, the process contract and the UI test ids. Send it to Richard and Nancy. A change goes back to the acceptance author.
3. **Not run against real code.** The live protocol groups (A5 to A8), the bridge (A10), the Host (A16) and the Playwright specs have compiled and have run only in the no-product state. They could not meet a real engine, Go referee or UI. Expect a first red run to show a contract mismatch, not a bug in the product.
4. **PIN.** Set after the last commit of this branch (see `git log -- acceptance/PIN`).
5. **Dave.** Ask if the X9 vector file may be committed. Until then it is made at run time.

## 8. Layout

| Path | Holds |
|---|---|
| `run.ps1`, `clauses.json`, `roles.json`, `skiplist.json`, `PIN` | The runner, the clause list that fixes M, cut roles, pinned skips, the pinned commit |
| `lib/Harness`, `lib/Live` | Clause runner, vector reader, process control, parsers, OpenSSL and Go referee wrappers (`Harness` links no product code; `Live` does) |
| `groups/<name>` | One console program per clause group, so an unbuilt slice cannot break a built one |
| `contract/` | The stub that holds the public signatures |
| `selftest/` | BCL stand-ins and the `SELF.*` clauses |
| `checks/docs_checks.py`, `tools/gen_clauses.py` | Text clauses and the clause list generator |
| `vectors/` | `.nsv` vectors, `SOURCES.md`, fetch scripts, extractors (`fetch-x9.ps1` downloads the X9.24-3 PDF to `_cache` with a recorded SHA-256) |
| `e2e/` | Playwright specs for A13 and the UI half of A16 (`npm ci` then `npx playwright test`; `run.ps1` does both) |
| `CONTRACT.md` | What the suite needs from the build. The referees are described in `referees/README.md` |

## 8. A17: per-type test keys, wizards and the vault (added 2026-11-05)

Conclusion: A17 adds **52 clauses**, so M is **260** (208 + 52). The A16 renames add none. Source: `docs/modes-design.md` and `docs/wizards-ux.md` on `main` at c65e1bb. The Host contract the clauses read is `CONTRACT.md` section 5.
Disposition: merge. Then the builders' slices V0 to V8 turn the clauses from NOT RUN to PASS one by one.

| Group | Clauses | Judge |
|---|---|---|
| `a17` (Host over HTTP and WebSocket, net10) | 39: readiness 2, personal-path warning 1, login walk 1, token 1, repo 1, vault 7, Show keys 5, flow walks 4, payment known-answer 1, lesson-key MAC 1, certificates and attacks 5, lessons on own keys 9, cold reader 1 | OpenSSL, Go `tokenverify`, the vault file read with Python sqlite3 and its master key, the suite's own SHA-256 and DUKPT reference |
| `a17probe` (links `NetSec.Core`, net10) | 6: TLS 1.3 server, TLS 1.1 server, TLS 1.3 client with an intermediate, SSH host key, SSH client key, no training key on a Credentials run | OpenSSL, Go `crypto/tls`, `ssh.exe`, Go `x/crypto/ssh`, on `ProbeRequest.Credentials` |
| `golden` (links `NetSec.Core`, net10 and CF) | 2: `A17.mock.golden-trace-equal` on each build | The traces recorded in `acceptance/golden/` before the key work began |
| `docs` (Python) | 4: `A17.ui.no-word-real`, `.ui.test-keys-line`, `.ui.no-outside-judge-line`, `.copy.grade-and-tics` | Flesch-Kincaid, tic-gate, pattern checks over `app/src` |
| `e2e` (Playwright) | 1: `A17.ui.show-keys-switch` | The browser |

The wizard is driven by step kind (explain, choose or generate, file, review, prove, done), so the state names of `modes-design.md` and `wizards-ux.md`, which differ, do not matter to the suite.

How a clause is proven to bite. `selftest/FakeHost/` is a Host built from `CONTRACT.md` section 5 and nothing else. `SELF.a17-clauses-pass-and-bite` runs each real clause on the faithful fake (it must PASS) and again on the fake with one named defect (it must FAIL). `ACC_SELF_LOG=<file>` writes the reason of each FAIL, so a person can check that each defect fails for the right reason. `SELF.a17-absent-host-is-not-run` runs every clause with no Host and expects NOT RUN `PRODUCT_MISSING`. The text, repository, cold-reader and referee clauses have stand-in trees of their own: `SELF.a17-text-checks-bite`, `SELF.a17-a15a-binding-bites`, `SELF.a17-repo-guard-bites`, `SELF.a17-cold-clause-bites`, `SELF.a17-intermediate-referee-bites`.
The five `a17probe` clauses also run on today's engines with `--prop a17probe.training=1`, which uses the training files and no `Credentials`. That proves the OpenSSL, `ssh.exe` and Go wiring on the real product (4 PASS, 1 has no training form).

Two rules from the lead. A clause on a type that no outside tool can judge (payment keys, the passkey-shaped login) says `known-answer` in its name or its text, and never reads as proved by a referee. The product's own word `Verified` never counts: only a referee in `acceptance/` does.

A15a: a verdict now binds to claim id plus a hash of the claim text, and to a hash of every step text and `textMine`. A verdict with no hash reads NOT RUN `ACCURACY_VERDICT_UNBOUND`, and one for changed text reads NOT RUN `ACCURACY_VERDICT_STALE`. The 12 existing verdicts carry no hash yet, so `A15a.tours.reader-verdicts` reads NOT RUN until each reader confirms and stamps the hashes (`python -I acceptance/checks/docs_checks.py --root . --hashes`).

Golden traces: record with `pwsh acceptance/run.ps1 -Clauses A17.mock.golden-trace-equal -RecordGolden`, then commit `acceptance/golden/`. Compare is the default. The recorder runs each lab three times and refuses to write a lab whose runs differ.
