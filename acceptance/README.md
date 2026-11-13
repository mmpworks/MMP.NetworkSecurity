# MMP.NetworkSecurity acceptance suite

Author: Echo. Date: 2026-11-05. Branch: `test/acceptance-suite`. Rule: D11. Builders never write under `acceptance/`.

Conclusion: the suite has **M = 378 product clauses** (`clauses.json`): the 208 of the first release, 54 for A17 (sections 8 and 12) and 73 for the AES walk, A19 (sections 10 and 11). With no product built it reports **0 of 378 PASS, 0 FAIL, 378 NOT RUN**.
Its 31 checks on itself all PASS. The suite is written against `docs/program-design.md` section 11, `docs/modes-design.md`, and the merged referees in `acceptance/referees`. Every group compiles against the contract stub on net10.0 and on net48 with the CF build of MMP.AsyncProxy.
Disposition: merge this branch. Send the open items in section 7 and in `CONTRACT.md` section 5.7 to Richard and Jared.

## 1. Run it

```
pwsh acceptance/run.ps1 -Clauses All                 # build what exists, run, write docs/_runs/acceptance-<timestamp>.json and .md
pwsh acceptance/run.ps1 -Clauses A1,A2               # ids, assertions, slices (S3), groups (tls13live) or prefixes (A5.client)
pwsh acceptance/run.ps1 -Clauses All -Fresh          # clone HEAD beside MMP.AsyncProxy, run the clone's own script, check PIN with tools/pin.py
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
| `SELF.waits-look-after-the-limit` | Each harness wait looks one last time after its limit (`lib/Harness/Poll.cs`). With a 0 ms limit and the answer already there, `Net.WaitPort` and `Poll.Until` see it |

Other proofs I ran by hand and do not keep in the repo:
1. A BCL-backed reference product (net10.0) with the A1 and A2 shapes, run through `run.ps1`: 21 of the 26 net10.0 A1 clauses PASS, and the four A2 primitive clauses PASS with 10,000 rounds each through a BCL oracle. The other clauses are NOT RUN because the reference lacks them (PRODUCT_MISSING). This run found one bug in the oracle reader (fixed).
2. A fake native library with the C ABI of `program-design.md` section 7: `A12.native.*` and the timing clause PASS on net10.0 and net48. Leaky \|t\| ran from 800 to 4,400 and constant-time \|t\| from 20 to 90 (cropped), so the 3 x rule holds with room.

## 3. How M is built

M is the length of `clauses.json` where `counts` is true. `tools/gen_clauses.py --write` makes the file from the clause code. The file is generated and never committed: `run.ps1` writes it at the start of every run and prints M, so a stale or missing copy cannot change a result, and no PR conflicts on it (#343). `SELF.clauses-json-matches-code` fails when the file and the code differ at the end of a run.
A PR diff no longer shows M, because the file is not committed. A PR that adds or removes clauses states it in the PR body as "M from X to Y", with both numbers from the `M =` line of a run before and after the change.

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
| A13 | A fresh clone beside the sibling. The walk compares the step ids shown with the tour file. `PIN` must match the clone's `acceptance/` tree (`tools/pin.py --check`) |
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
| 14 | `PIN` holds `acceptance-tree <hash>`: the git tree hash of `acceptance/` with `PIN` left out. Every PR that changes `acceptance/` runs `python -I acceptance/tools/pin.py --write` and commits `PIN` in the same PR. The gate runs `pin.py --check` on every PR and names a stale `PIN` (`PIN_STALE`). The committed setting `"pin": true` in `acceptance/settings.json` turns the check on, never the presence of `PIN`, so a deleted `PIN` fails by name (`PIN_MISSING`). `"pin": false` reads `PIN_OFF`, and the fresh-clone clause is then NOT RUN. A second gate check in `tools/` refuses a PR that changes `acceptance/` together with any path outside `acceptance/` and `docs/`, so only an acceptance PR moves `PIN` | A PR cannot know the commit it merges as, and a commit cannot name itself. A tree hash is known before the merge. The commit form went stale across many PRs, because only a `-Fresh` run looked |
| 15 | `A15a` reads `claims [{text, source}]` at the top of each tour file (section 11), and also from a step, and verdict files by lesson | Section 11 names the shape, not the place |
| 16 | `skiplist.json` is empty | No skip is justified yet |

## 6. NOT RUN reasons that are not PRODUCT_MISSING

In the run above: `NOT_A_FRESH_RUN` for `A13.fresh-clone.acceptance-unchanged` (1 clause).
These appear later by design, each named in the report: `REFEREE_MISSING`, `REFEREE_VERSION`, `REFEREE_PROTOCOL`, `ROLE_CUT:<role>`, `LESSON_NOT_BUILT`, `NO_LESSON_INSTALLS_KEYS`,
`ACCURACY_READER_PENDING`, `NO_CLAIMS_DECLARED`, `UI_CONTROL_MISSING`, `VECTORS_MISSING`, `SIBLING_MISSING`, `TOOL_MISSING`, `PIN_OFF`, `WIZARD_PART_NOT_BUILT`, `FILE_ROW_NOT_BUILT`.

`UI_CONTROL_MISSING` is NOT RUN only when `"unbuilt"` in `acceptance/settings.json` names the control key. The list is empty by default. Any other missing control is a FAIL. The report's reason column says `ASSERTION`, and the detail starts with `UI_CONTROL_MISSING_ON_SHIPPED_SCREEN:`, then the same text (#372). A new screen's clauses go in with their control keys on the list. The PR that runs them green takes the keys off.

## 7. Open items

1. **Referees.** Jared's `acceptance/referees/go` and `bcl` are merged. The suite reads their JSON events, the first-line port, the tap log format and the BCL oracle protocol from `acceptance/referees/README.md`. `SELF.referee-protocols` runs the real programs. The old `referee-contract.md` is deleted.
2. **Contract.** `CONTRACT.md` lists the ASSUMED members, the process contract and the UI test ids. Send it to Richard and Nancy. A change goes back to the acceptance author.
3. **Not run against real code.** The live protocol groups (A5 to A8), the bridge (A10), the Host (A16) and the Playwright specs have compiled and have run only in the no-product state. They could not meet a real engine, Go referee or UI. Expect a first red run to show a contract mismatch, not a bug in the product.
4. **PIN.** After the last `acceptance/` commit of a branch, run `python -I acceptance/tools/pin.py --write` and commit `acceptance/PIN`.
5. **Dave.** Ask if the X9 vector file may be committed. Until then it is made at run time.

## 8. Layout

| Path | Holds |
|---|---|
| `run.ps1`, `clauses.json`, `roles.json`, `skiplist.json`, `PIN` | The runner, the clause list that fixes M (generated by each run, not committed), cut roles, pinned skips, the pinned `acceptance/` tree |
| `lib/Harness`, `lib/Live` | Clause runner, vector reader, process control, parsers, OpenSSL and Go referee wrappers (`Harness` links no product code; `Live` does) |
| `groups/<name>` | One console program per clause group, so an unbuilt slice cannot break a built one |
| `contract/` | The stub that holds the public signatures |
| `selftest/` | BCL stand-ins and the `SELF.*` clauses |
| `checks/docs_checks.py`, `tools/gen_clauses.py` | Text clauses and the clause list generator |
| `vectors/` | `.nsv` vectors, `SOURCES.md`, fetch scripts, extractors (`fetch-x9.ps1` downloads the X9.24-3 PDF to `_cache` with a recorded SHA-256) |
| `e2e/` | Playwright specs for A13 and the UI half of A16 (`run.ps1` runs `npm ci` when `node_modules` is missing, then `tsc` and Playwright from that folder's own `node_modules` under node, never through npx) |
| `CONTRACT.md` | What the suite needs from the build. The referees are described in `referees/README.md` |

## 8. A17: per-type test keys, wizards and the vault (added 2026-11-05)

Conclusion: A17 adds **53 clauses**, so M is **261** (208 + 53). The A16 renames add none. Source: `docs/modes-design.md` and `docs/wizards-ux.md` on `main` at c65e1bb. The Host contract the clauses read is `CONTRACT.md` section 5.
Disposition: merge. Then the builders' slices V0 to V8 turn the clauses from NOT RUN to PASS one by one.

| Group | Clauses | Judge |
|---|---|---|
| `a17` (Host over HTTP and WebSocket, net10) | 39: readiness 2, personal-path warning 1, login walk 1, token 1, repo 1, vault 7, Show keys 5, flow walks 4, payment known-answer 1, lesson-key MAC 1, certificates and attacks 5, lessons on own keys 9, cold reader 1 | OpenSSL, Go `tokenverify`, the vault file read with Python sqlite3 and its master key, the suite's own SHA-256 and DUKPT reference |
| `a17probe` (links `NetSec.Core`, net10) | 6: TLS 1.3 server, TLS 1.1 server, TLS 1.3 client with an intermediate, SSH host key, SSH client key, no training key on a Credentials run | OpenSSL, Go `crypto/tls`, `ssh.exe`, Go `x/crypto/ssh`, on `ProbeRequest.Credentials` |
| `golden` (links `NetSec.Core`, net10 and CF) | 2: `A17.mock.golden-trace-equal` on each build | The traces recorded in `acceptance/golden/` before the key work began |
| `docs` (Python) | 4: `A17.ui.no-word-real`, `.ui.test-keys-line`, `.ui.no-outside-judge-line`, `.copy.grade-and-tics` | Flesch-Kincaid, tic-gate, pattern checks over `app/src` |
| `e2e` (Playwright) | 1: `A17.ui.show-keys-switch` | The browser |

The wizard is driven by step kind (explain, choose or generate, file, review, prove, done), so the state names of `modes-design.md` and `wizards-ux.md`, which differ, do not matter to the suite.

How a clause is proven to bite. `selftest/FakeHost/` is a Host built from `CONTRACT.md` section 5 and nothing else. `SELF.a17-clauses-pass-and-bite-*` (4 rows by area) runs each real clause on the faithful fake (it must PASS) and again on the fake with one named defect (it must FAIL). `ACC_SELF_LOG=<file>` writes the reason of each FAIL, so a person can check that each defect fails for the right reason. `SELF.a17-absent-host-is-not-run` runs every clause with no Host and expects NOT RUN `PRODUCT_MISSING`. The text, repository, cold-reader and referee clauses have stand-in trees of their own: `SELF.a17-text-checks-bite`, `SELF.a17-a15a-binding-bites`, `SELF.a17-repo-guard-bites`, `SELF.a17-cold-clause-bites`, `SELF.a17-intermediate-referee-bites`.
The five `a17probe` clauses also run on today's engines with `--prop a17probe.training=1`, which uses the training files and no `Credentials`. That proves the OpenSSL, `ssh.exe` and Go wiring on the real product (4 PASS, 1 has no training form).

Two rules from the lead. A clause on a type that no outside tool can judge (payment keys, the passkey-shaped login) says `known-answer` in its name or its text, and never reads as proved by a referee. The product's own word `Verified` never counts: only a referee in `acceptance/` does.

A15a: a verdict now binds to claim id plus a hash of the claim text, and to a hash of every step text and `textMine`. A verdict with no hash reads NOT RUN `ACCURACY_VERDICT_UNBOUND`, and one for changed text reads NOT RUN `ACCURACY_VERDICT_STALE`. The 12 existing verdicts carry no hash yet, so `A15a.tours.reader-verdicts` reads NOT RUN until each reader confirms and stamps the hashes (`python -I acceptance/checks/docs_checks.py --root . --hashes`).

Golden traces: record with `pwsh acceptance/run.ps1 -Clauses A17.mock.golden-trace-equal -RecordGolden`, then commit `acceptance/golden/`. Compare is the default. The recorder runs each lab three times and refuses to write a lab whose runs differ.

## 10. A19: the AES walk, chapter 1 (added 2026-11-06)

Conclusion: A19 adds **46 clauses**, so M is **307** (261 + 46). Source: `docs/walkthrough-design.md` (Jared's pass on d1368af, PR #146), slices W1a and W1b. Every clause reads NOT RUN `PRODUCT_MISSING` until the walk exists.

| Group | Clauses | Judge |
|---|---|---|
| `walk` (links `NetSec.Core`, net10 and CF) | 26: 13 on each build. Round states C.1 to C.3 in both directions 6, key rows 3, tables 1, step order 1, real path and RefAes 1, BCL 1 | FIPS 197 (2001) data in `vectors/aes-fips197-rounds.nsv`, RefAes, the BCL oracle |
| `a17` (Host over HTTP and WebSocket, net10) | 7: tables 1, real run on 2 seeds 1, Show keys OFF 1, no-store 1, refusals 1, no trace event 1, control label 1 | The key from a live trace, RefAes, the BCL |
| `docs` (Python) | 3: no table under `app/src`, the words of design 2.6, every walk route listed | Script |
| `e2e` (Playwright) | 10: first view 1, grid order 1, step order 1, text by Next 1, S-box click 1, Show keys OFF line 1, flip race 4 | The browser against the Host's own reply |

Anchor rules:

1. No expected value comes from product code. `RefAes` (`lib/Harness/RefAes.cs`) shares no code with `NetSec.Core` and builds its S-box from the field inverse.
2. `pdftotext` prints some FIPS values one line above their label, so `extract_nist.py` reads the n-th value for the n-th label. A reader that matches a label to the value on its line gets 370 values and wrong labels.
3. `SELF.walk-vector-flip-fails` changes one hex digit of each of the 372 values in a copy of the file, and each change FAILS its clause.
4. `SELF.walk-clauses-pass-and-bite` and the rows `A19.host.*` of `SELF.a17-clauses-pass-and-bite-walk-host` run a canned walk, and the clauses FAIL it.

Limit: the e2e clauses have never run against a built panel. Their test ids are ASSUMED (`CONTRACT.md` section 6).

Disposition: merge. Then Richard builds W1a and Nancy builds W1b. Chapter 2 clauses arrive in a second PR.

## 11. A19: animation, key schedule, finite field (added 2026-11-06)

Conclusion: these add **24 clauses**, so M is **331** (307 + 24). Source: `docs/walkthrough-design.md` at c19b151, sections 2.2a to 2.2d, 2.4, 3.3 to 3.5, and the expanded table of #156 (main at 4ffba13).

| Group | Clauses | Judge |
|---|---|---|
| `walk`, net10 and CF | 10: 5 on each build. Terms, worked example, round constants, shift map, one-bit spread | The design's worked examples, FIPS 197, `RefField` |
| `a17`, Host over HTTP | 4: tables, terms on 2 seeds, Show keys OFF holds no word or term, `match` on the `L1-use-ecb` fork | `RefField`, `RefAes`, a live trace |
| `docs` | 2: definition lines at the reading grade, GCM panel line | `checks/walk_lines.json` |
| `e2e` | 8: end frames, reduced motion with its motion-on control, Play stops at the round's end, flip during Play, expanded table, word build, key band, one real multiply | The browser against the Host's own reply |

Limit: `A19.ui.end-frames-on-all-key-sizes` and `A19.ui.key-band-on-192-and-256` read NOT RUN until W1c builds the key sizes, and `A19.app.gcm-panel-names-the-field` reads NOT RUN until W1c builds the GCM panel. So the W1 kill condition reads those 3 as W1c work. The GHASH, forgery and tap-a-byte clause themes of #155 arrive with W1c and W2.

Disposition: merge after section 10.

## 12. A17: the `.security` fallback (added 2026-11-06)

Conclusion: `A17.security.fallback-finds-the-repo-folder` adds **1 clause**, so M is **332**. Every other suite run sets `NETSEC_SECURITY_DIR`, so before this clause no test ran the path a learner gets. The clause copies the built Host under a stand-in repository, so it never touches the real `.security/`.

Limit: the last branch of `SecurityStore.ResolveRoot`, with no `.git` above the Host, is not run. A temp folder may have a `.git` above it on some machines, so the result would depend on the machine.

Disposition: merge after sections 10 and 11.

## 13. A19: the round constant steps and the word test (added 2026-11-06)

Conclusion: `A19.host.rcon-steps` adds 1 clause, and `A19.walk.word-test` adds 2 (one per build), so M is **335**. Source: `docs/walkthrough-design.md` section 2.2b, from #169 and #172. The on-screen themes of that section arrive in the W1b set.

Disposition: merge before W1a.

## 14. A18: what each engine leaves out (added 2026-11-06)

Conclusion: the line clauses add **8 clauses**, so M is **343**. Source: `docs/conformance-matrix.md`, the 8 rows marked PATH OK, GAPS. 6 FAIL on `main` until the tour words land, and 2 pass already, because #149 fixed lesson 6.

| Item | Rule |
|---|---|
| Data | `checks/engine_limits.json` holds each lesson's required words, the source its claim must cite, and banned phrases |
| Line | One tour step holds the whole line. That step carries a claim whose source names the standard |
| Self-check | `SELF.a18-lines-bite`: each example line PASSES, and each one-change tour FAILS |

Disposition: merge, then Richard and Nancy write the words. The refusal clauses and the BCL clause arrive in their own PRs.

## 15. A18: the refusal pins (added 2026-11-06)

Conclusion: the refusal clauses add **32 clauses**, so M is **375**. All pass on main's engines. Each pairs with a line of section 14, so a change to the engine shows which line needs a change. 17 of the 19 clause names run a control first. The other 2 (`tls11.no-resumption`, `tls11.no-client-certificate-request`) read one session that must complete. No self-check covers them, because they need real engines and real peers.

Disposition: merge after section 14.

## 16. A2: RSA against the .NET library (added 2026-11-06)

Conclusion: `A2.rsa.pkcs1` adds **2 clauses**, one per build, so M is **377**. Source: `docs/conformance-matrix.md` row 29, by Steve's ruling that a library comparison is the evidence where the library can check a primitive. Before this, RSA had OpenSSL-made vectors, live TLS 1.1, and a library check of its key format only.

Disposition: merge after section 15.

## 17. A19: the practice key at 192 and 256 bits (added 2026-11-06)

Conclusion: `A19.host.practice-key-192-256` adds **1 clause**, so M is **378**. Source: `docs/walkthrough-design.md`, the "Which key runs?" row. It runs when the Host has the walk route (#178).

Disposition: merge after section 16.

## 18. AO: the Algorithm-Optimization anchor (added 2026-11-11)

Conclusion: the AO rows are the anchor of `docs/algorithm-optimization-prd.md` section 3. They were written before any product change, and `acceptance/ao-rows.tsv` lists the state that each row must show at each slice.

| Part | Where |
|---|---|
| AO-2 differential, AO-3 tables, AO-7 walk, frozen 5c5d4a4 copy | `groups/algo`, `groups/algo/Frozen` (made by `tools/freeze_ref.py`) |
| AO-4 threads and the payload worker, in a process of its own | `groups/algothreads` |
| AO-0 row-list check, AO-1 and AO-8 row sums | `run.ps1` driver rows |
| Row list and bench report shape | `ao-rows.tsv`, `ao-bench-schema.md` |

Run: `pwsh acceptance/run.ps1 -AoSlice S0 -Clauses AO [-AoBenchReport PATH]`. `-AoSlice` has no default. With no bench report, the bench rows read as absent, so AO-0 is FAIL.

Disposition: merge into `Algorithm-Optimization`. The S0 close needs the bench report of the merged head.

## 19. AO: caller-buffer forms, budgets and the cf meter (added 2026-11-11)

Conclusion: the rows that S1 to S4 need for the zero-garbage rules of PRD 7.4 exist before S1 starts. They read NOT RUN PRODUCT_MISSING until their form exists.

| Part | Where |
|---|---|
| AO-5 caller-buffer rows, 0 B for the whole call (PRD 7.3 item 15) | `groups/algo/AoAlloc.Product.cs`, bound through closed delegates in `AoSide.Product.cs` |
| AO-2 caller-buffer rows: separate, same index, apart in one array, partial overlap refused (`ARG_RANGES_OVERLAP`), short nonce refused (`GCM_NONCE_LENGTH`), bad tag leaves the output all 0 | `groups/algo/AoInto.cs`, `AoInto.Product.cs` |
| Byte budgets, a row with no line held to 0 | `ao-budgets.tsv` (header: Jared's 3 conditions), read by the AO-5 clause and by AO-0 |
| The cf AO-5 rows: `AppDomain.MonitoringTotalAllocatedMemorySize`, 1,000,000 blocks per op, zero against not zero | `groups/algo/AoAllocMeter.cs` |
| AO-4: a kept result array is cleared after `done`, and the copy taken inside `done` stays right | `groups/algothreads/AoWorker.cs` |

Limit of the cf meter: the counter moves in 8,192-byte steps, so an allocation total under 8,192 B over the run is unseen. Each cf row prints its call count and this limit.

Disposition: merge into `Algorithm-Optimization` before S1.

## 20. AO: streamed CBC and CTR, and Verify with offsets (added 2026-11-11)

Conclusion: each remaining form of PRD 7.3 item 15 has an AO-2 row and an AO-5 row. They read NOT RUN PRODUCT_MISSING until their form exists.

| Part | Where |
|---|---|
| AO-2 `aes-cbc-stream`, `aes-ctr-stream`: one `CbcChain` or `CtrCounter`, 1 or 2 messages, 1 to 4 calls for each message, each call with its own aliasing | `groups/algo/AoStream.cs`, `AoStream.Product.cs` |
| AO-2 `aes-cmac-verify-into`, `aes-cmackey-verify-into`: the right tag at an offset, then no change, one changed tag bit, or one changed message bit | the same files |
| AO-5 for the 4 forms: 0 B for Init, one call and Clear on one object used again; 0 B for a Verify call | `groups/algo/AoAlloc.Product.cs` |
| The seams: the state type and the overload are found by name, and bound as typed delegates | `AoSeams.TryStream`, `TryCmacVerifyInto`, `TryCmacKeyVerify` in `groups/algo/AoSide.Product.cs` |
| Self-check, 24 planted faults (PRD 7.4 rule 5 and 7.3 item 15: a call before Init, after Clear, after a partial CTR block; a second Init that keeps the state of the first message; the state checked before the arguments; a refused call that ends the object; a short Init accepted; a null state object not named; a refused Init that empties the object; a subtype of `InvalidOperationException`; `ArgumentException` for a range fault; a Verify that skips a tag byte) | `SELF.ao2-stream-control-and-planted-faults` in `selftest/SelfAo.cs` |
| The binder runs on stand-in types of the item 15 shape: Init, the overload and Clear are called in order; a null state object reaches the overload; a value return, a class that is not sealed and a class with no Clear read `SIGNATURE_NOT_CONFIRMED` | `SELF.ao-stream-bind-runs-on-stand-in-types` in `selftest/SelfAoStreamBind.cs`, on `groups/algo/AoStreamBind.cs` |
| The GCM check order of PRD 7.3 item 15 (the nonce length before the overlap): a planted fault that checks the overlap first goes red | `gcm-overlap-checked-before-nonce` in `SELF.ao2-into-control-and-planted-faults` |

The rows bind to the signatures of PRD 7.3 item 15 (the streamed forms, the state objects, and Verify with offsets).

The rules of the reference model, each from PRD 7.3 item 15 (the 5c5d4a4 code has no streamed form):

1. The calls of one message give the bytes of one frozen call over the joined input.
2. A call checks its arguments first, then the state. A null state object throws `ArgumentNullException`. A null input or output array throws `ArgumentNullException`, and a range outside its array throws `ArgumentOutOfRangeException` (the frozen `Arg.Range`). A CBC count that is not a multiple of 16 is refused with the exception of the frozen form. A partial overlap is refused with `ARG_RANGES_OVERLAP`.
3. A call on an empty or ended object throws `InvalidOperationException`. The object is empty when new and after Clear. It is ended after a CTR call with a partial block.
4. A refused call changes neither the state object nor the output. The case goes on after a refused call, so a change shows in the next call.
5. Init is legal in every state. A null array throws `ArgumentNullException`. Fewer than 16 bytes from the offset throws `ArgumentOutOfRangeException`. A refused Init leaves the object as it was: after one, half of the messages have no good Init, and their calls run on the old state.
6. Each exception is compared by its type name, so a subtype is a difference.

Limits:

1. A call has one null or range fault at most. The PRD gives no order between the input and the output array.
2. No case gives Init a negative offset.
3. `Tls13Records` (one direction, one thread) is a product test. It has no acceptance row.
4. The Verify rows check the answer. They do not check that the compare takes constant time (PRD 7.4 rule 8, and non-goal 3).
5. The binder has run on stand-in types on .NET 10 only. Its first run on the product's types, and on the .NET Framework 4.8 runtime, is the first S1 run.

Disposition: merge into `Algorithm-Optimization` before the S1 code that adds these forms.

## 21. A break in the suite's own code is a FAIL (added 2026-11-11)

Conclusion: a clause group that does not compile because of acceptance code reads FAIL `ACCEPTANCE_COMPILE_ERROR` in every slice. It no longer reads NOT RUN `PRODUCT_MISSING`.

What happened: the thread group links `groups/algo/AoSide.Product.cs`. That file started to use `AoStreamSeam`, and the thread group did not link the new file. The compiler gave CS0246, the code for a missing name. The runner read every such code as a missing product type, so 2 rows that must PASS at S0 read NOT RUN `PRODUCT_MISSING`. `AO-0.row-list-matches` showed it. In a group where every row is NOT RUN `PRODUCT_MISSING` before its slice, the same break gives no red.

| Part | Where |
|---|---|
| The verdict of a failed group build. A missing name that `acceptance/groups` or `acceptance/lib` declares is the suite's own, and the group is FAIL `ACCEPTANCE_COMPILE_ERROR`. A name that `contract/` or a `Frozen/` folder also declares counts as a product name | `Get-GroupBuildVerdict` and `Get-SuiteTypeNames` in `run.ps1` (CONTRACT.md rule 4) |
| Self-check: a real project that names `AoStreamSeam` without its file must read FAIL; 6 recorded compiler lines, each with its verdict | `SELF.suite-compile-break-is-a-fail` in `run.ps1` |

Limit: the check reads the first quoted name of the errors CS0246, CS0234, CS0103, CS1061 and CS0117. A break of the suite that gives only another missing-symbol code (for example CS1503, a wrong argument type) still reads NOT RUN `PRODUCT_MISSING`.

Disposition: keep. A group build that fails for a missing product name stays NOT RUN `PRODUCT_MISSING`, as before.

## 22. A bench report is judged by the code it measured (added 2026-11-12)

Conclusion: a bench report is valid on a head that has the same measured code and data as the commit the report names. The rule no longer compares the commit id with the head.

Why: the old rule (the report's `commit` equals the head) could never hold for a report that is committed on its branch. The commit that adds the report changes the head, and a rebase does the same. Every bench row then read FAIL `AO_BENCH_OTHER_COMMIT`.

| Part | Where |
|---|---|
| The rule: equal git object ids at the measured paths; `bench/files` by content, one to one | `Get-AoBenchCodeVerdict` in `run.ps1`; rule 6 of `ao-bench-schema.md` |
| A report whose commit the repository does not hold reads FAIL `AO_BENCH_COMMIT_UNKNOWN` | the same function |
| Self-check on a small git repository, 25 cases, and 2 more through `Read-AoBench` | `SELF.ao-bench-same-code-rule-bites` in `run.ps1` |
| The 2 random test files have the names `large-4mib.dat` and `small-1k.dat` (they were `.bin`) | `ao9-files.tsv` |

The measured paths: `src/NetSec.Core`, `src/NetSec.Core.NetCF`, `src/AsyncProxy.Local`, `src/AsyncProxy.Local.NetCF`, `acceptance/groups/algo/Frozen`, the build files `Directory.Build.props`, `Directory.Build.targets`, `src/Directory.Build.props`, `src/Directory.Build.targets`, `Directory.Packages.props`, `global.json` and `NuGet.config` (a file that both sides lack is equal), and each entry of `bench/` but `bench/files`. They are the projects that the bench projects reference, the frozen original they compile, the build files that MSBuild and NuGet read from outside those folders, and the bench code. 6 of the 7 build files do not exist today; they are on the list so that a new one makes a report stale.

Limits:

1. The report states its commit. The suite cannot prove that the benchmark ran on that commit. This is the same as before.
2. The whole product project folders count. A change in `src/NetSec.Core` outside the crypto code makes the report stale.
3. The sibling MMP.AsyncProxy repository is outside this repository, and the rule does not see it.
4. The measured commit must stay in the repository. After a rebase it is on no branch, so the benchmark owner pushes a tag on it. A later bench schema can write the tree ids into the report, and then no tag is needed.

Disposition: keep.

## 23. A run report holds no path of the machine (added 2026-11-12)

Conclusion: a detail is stored with its local folders made relative, and a run whose report still holds a local path fails by name.

Why: each run report goes into a public repository. On 2026-11-12 one detail printed the folder of a bench report, with the user folder in it. That report was not committed. Each report before held the worktree root as a drive path in 3 kinds of place.

| Part | Where |
|---|---|
| A detail is made relative before it is stored: the product root becomes `.`, and the work folder, the AsyncProxy folder, the CF reference folder, the temp folder and the user folders each get a name such as `<work>` or `<home>` | `Hide-LocalPaths`, called by `Set-Result`, in `run.ps1` |
| The summary field `productRoot` is `.` | `run.ps1` |
| The last look: a drive path, a path under a `Users` folder, or the user name that is still in a detail, or in the json or md text, is replaced by `<local path>`. The run prints `REPORT_HOLDS_LOCAL_PATH` with the clause ids, the summary lists them in `localPathLeaks`, and the exit code is 1 | `Find-LocalPaths` in `run.ps1` |
| Self-check: 7 texts made relative, 5 texts searched, and the real folders of the run through `Set-Result` | `SELF.run-report-has-no-local-path` in `run.ps1` |

Limits:

1. The machine name stays in the summary field `machine`.
2. The lines that the run prints on the console (`report:`, `json:`) hold the full path. A log of a run is not a run report.
3. The reports from before this change keep their paths.
4. A path with a space ends at the space for the last look, so the text after the space stays.

After the review of this change (2026-11-12): the json is written last, and its summary field `localPathLeaks` lists every leak, also one that the last look finds in the md text or in a summary field (`Get-ReportTexts` in `run.ps1`). Before, the field listed the detail leaks only.

Disposition: keep.

## 24. Before S1 code: the 5x test on 6 rows, the CMAC tag overlap, the static GCM open row (added 2026-11-12)

Conclusion: 4 changes from the design review of slice S1 are in the suite before any S1 code exists.

| Change | Where |
|---|---|
| Schema rule 3: from slice S1, each of the 6 net10 AES throughput rows needs a code ratio of 5.00 or more, else FAIL `AO6_BELOW_TARGET`: `AO-6.aes-block.net10`, `AO-6.aes-ecb.net10`, `AO-6.aes-cbc.net10`, `AO-6.aes-ctr.net10`, `AO-6.aes-gcm.net10`, `AO-6.aes-cmac.net10`. Before, the rule judged `AO-6.aes-block.net10` only | `$AoSpeedTargetRows` and `Read-AoBench` in `run.ps1`; rule 3 of `ao-bench-schema.md` |
| Self-check of rule 3: 4.99 x reads FAIL on each of the 6 rows at S1 and at S4, 5.00 x reads PASS, 4.99 x at S0 only records, and 2 rows outside the rule stay PASS | `SELF.ao6-speed-target-bites` in `run.ps1` |
| The CMAC tag range against the message range (PRD 7.1.9): the same index and ranges apart are legal, any other overlap is `ARG_RANGES_OVERLAP`. The cases of `aes-cmac-into` and `aes-cmackey-into` draw the 4 aliasings | `FrozenInto.Cmac` and `AoIntoDiff` in `groups/algo/AoInto.cs` |
| A planted product that skips that check goes red, for `Cmac.Compute` and for `CmacKey.Compute` | `accepts-partial-overlap` in `SELF.ao2-into-control-and-planted-faults` |
| The bench schema field `runtime` has the name `mergeRuntime`: it is the runtime of the process that merged the parts. The runtime of a row is in its id. The suite does not read the field | `ao-bench-schema.md` |
| A row for the static `Gcm.TryOpen` wrapper, with the budget of the static `Gcm.Seal` wrapper (PRD 7.3 item 16): both build a `GcmKey` on each call | `AO-5.aes-gcm-static-open.net10` in `groups/algo/AoAlloc.Product.cs`, `ao-rows.tsv`, `ao-budgets.tsv` |

| The `tradeoff_pr` field of a budget line above 0 is a PR number (`#` and digits). Any other text is a red, in the AO-5 clause (`AO_BUDGET_NO_TRADEOFF`) and in `AO-0`. So a text that stands for a number that is still to come cannot merge | `AoBudgets.IsPrNumber` in `groups/algo/AoBudgets.cs`, `Get-AoBudgetReds` in `run.ps1`, condition 4 in the header of `ao-budgets.tsv`; self-check cases in `SELF.ao-row-list-bites` and `SELF.ao5-meter-bites` |

The row list has 210 rows (209 before).

The row set of rule 3 and the value 5.00 were fixed on 2026-11-12, before any S1 code. A change of either is a decision of the lead or of the owner, recorded before the PR that makes it merges.

Limits:

1. Rule 3 judges the numbers of the bench report. The suite cannot prove them; it checks that the report is for the measured code (section 22).
2. `AO-6.aes-key-setup.net10` is an AES row and no throughput row. Rule 3 does not judge it.
3. No product has the caller-buffer CMAC forms yet, so the overlap cases have run against the reference model and the planted fault only.

Disposition: keep.

## 25. What the row AO-6.aes-gcm.net10 times (added 2026-11-13)

Conclusion: the row `AO-6.aes-gcm.net10` times a held `GcmKey`. The key object is built outside the timed loop.

| Item | Value |
|---|---|
| Decision | the owner, 2026-11-13, recorded before the merge of #433 (the S1 code) |
| The timed call | the seal of a 1024-byte message with no AAD on one `GcmKey`; the unit is one 16-byte block |
| The baseline | the static `Gcm.Seal` of the 5c5d4a4 code on the same message |
| Not in this row | the static `Gcm.Seal` and `Gcm.TryOpen` wrappers of the head. They build a `GcmKey` on each call |
| Where the wrappers are held | `AO-5.aes-gcm-static.net10` and `AO-5.aes-gcm-static-open.net10`, budget 4.875 B per block, tradeoff PR #433. No change |
| Rule 3 | no change: the 6 rows, a code ratio of 5.00 or more from slice S1 |
| Where | rule 3 of `ao-bench-schema.md` |

Why this is a rule change and no edit inside a PR: section 24 says that a change of the row set of rule 3 or of 5.00 is a decision of the lead or of the owner. This change keeps both. It changes what one of the 6 rows times, after numbers of the first form were seen. So the owner made the decision, and it was recorded before the S1 code merged.

Limits:

1. The suite reads the numbers of the bench report. It cannot see which call the benchmark timed. The benchmark code and its review hold that.
2. The S0 bench report (commit 46b2a41) timed the static `Gcm.Seal`, because the S0 code has no `GcmKey`. At S0 the row only records, so that report stays valid for S0.

Disposition: keep.
