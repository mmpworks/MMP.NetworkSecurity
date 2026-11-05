pwsh E:\dev\MMP.NetworkSecurity\tools\open-app.ps1

# Closing report: MMP.NetworkSecurity, 2026-11-05

Result: 207 of 208 clauses PASS, 1 FAIL, 0 NOT RUN, from a fresh clone, by an agent that wrote none of the code.
Disposition: the course is usable on the desktop now. Nothing has run on real CE.

Two things for Steve to do:
1. Answer one question: what runs on the CE box, and who starts the SSH? The choices are in `docs/prd.md`, Assumptions, item 4. Also read the box's SSH version banner, because that decides if it is the old kind of peer.
2. Decide on real mode, the one failed clause. It is unbuilt.

## 1. The run

Command: `pwsh acceptance/run.ps1 -Clauses All -Fresh -SelfTest -NetCFRefDir "E:\dev\tools\netcf35-ref"`.
Run 08:23 to 08:38 on product commit `ccbe229`, acceptance commit `6f1005d`. Main is now `a6f3a96`; `git diff ccbe229 a6f3a96` shows only `README.md` and `THIRD-PARTY-NOTICES.md`.

```
[acceptance] 207 of 208 clauses PASS (1 FAIL, 0 NOT RUN); M = 208
[acceptance] self-checks: 24 of 24 PASS
```

Every clause, by id: `docs/_runs/acceptance-20261105-082311.md`. `acceptance/clauses.json` holds 232 entries: 208 counted clauses and 24 self-checks.

| Assertion | What it judges | Referee | PASS of M |
|---|---|---|---|
| A1 | Primitives on both builds | Published vectors | 52 of 52 |
| A2 | Primitives, 10,000 seeded rounds | .NET 10 BCL | 12 of 12 |
| A3 | AES DUKPT | x9.org vectors | 15 of 15 |
| A4 | TLS 1.3 key schedule | RFC 8448 | 20 of 20 |
| A5 | TLS 1.3, both roles, hybrid | OpenSSL 3.5.7, Go | 20 of 20 |
| A6 | Key log | OpenSSL 3.5.7 | 4 of 4 |
| A7 | TLS 1.1, both roles | OpenSSL 3.5.7 | 12 of 12 |
| A8 | SSH, both roles | Go x/crypto, ssh.exe | 12 of 12 |
| A9 | CF binaries, same suite on net48 | CF references | 4 of 4 |
| A10 | CE path, tampers, privacy | Go, taps, ssh.exe | 7 of 7 |
| A10a | Trace equals the wire | Go tap | 3 of 3 |
| A11 | Tokens, DPoP, mutual TLS, attack rows | Go tokenverify, Go TLS | 9 of 9 |
| A12 | Native compare, timing | cl.exe, live run | 8 of 8 |
| A13 | App walks, 11 lessons, fresh clone | Playwright | 15 of 15 |
| A14 | Tour bindings, concept cap | Live Host | 2 of 2 |
| A15 | Reading grade, tics | Script | 2 of 2 |
| A15a | Accuracy rules, independent reader | Reader verdicts | 3 of 3 |
| A16 | Types, Host rules, real mode | Tests, OpenSSL key log | 7 of 8 |

The clause not met: `A16.real-mode.os-transport-writes-no-secret-bytes`. The Host answers `REAL_MODE_NOT_BUILT`. The Real mode button only changes the label to OS TRANSPORT, and the error appears when the next lesson starts. `OsTransportFactory` was the S8 item and was never built.

The kill condition was met at 08:38: every clause has a recorded result. No work followed except this report.

First command, run on main at 08:40 with `-Smoke`: `open-app: window title: 'Network Security Lab'`, `open-app: smoke ok`.

## 2. What is not proved

1. **Nothing ran on CE.** The wording is "CF-compiled, run on the desktop CLR, never run on CE". There is no CE compiler, emulator or device here.
2. **No real old SSH peer ran.** Windows ssh.exe 9.5p2, Git ssh 10.3p1, plink 0.80 and Go all offer the strict KEX marker. With the marker off on our side, the path ran against our own code and ssh.exe on both suites, and once against Go.
3. **The legacy CE path has no A10 clause.** The proof is `BridgeLiveTests`, a builder test through five real processes, with our own gateway as the other end. A10 runs the modern suite.
4. **Review tier.** Jared's reviews and the accuracy reader ran on the same vendor as the builders. The anchors are the referees, published vectors and live attacks. A second vendor did not read this.
5. **DUKPT text sources.** ANSI X9.24-3 is paid. General DUKPT claims rest on labelled secondary sources. The test vectors come from x9.org at run time and stay out of git.
6. **One unnamed hang.** A whole test run sat idle for about 40 minutes once, and an A9 run timed out once at 900 s, with no test frame in the sample. Each is seen once. The gate and A9 now end a stuck test at 3 minutes and name it, and it did not recur in the closing run.
7. **Accuracy pass.** 137 of 137 claims read accurate, counted from `docs/_verdicts/`, and the tours hold 140 steps and 137 claims. The reader also read the step text against labs run in-process, outside the app, so UI statements were not run. Clause A15a reads claim verdicts only: it never reads the step-text result and never matches verdicts to the current tour. PR #80 and PR #95 changed labs after the last lesson 9 read, and no step was re-read after them.

## 3. Known limits in the product

1. TLS two-way bulk above approximately 16 MiB fails by name, sometimes after 30 s. SSH carried 96 MiB. No lab, sale or bridge hop reaches this.
2. One injected clear record ends a session, by name. It gives no login.
3. The CE cannot check the bank's reply. Lesson 9 teaches this.
4. The TLS 1.1 client refuses server RSA keys below 2048 bits (RFC 9325 section 4.5). A real device's peers may use smaller keys. That is unknown.
5. The client name check compares a name only. A CA that issues the allowed name to the wrong key still passes. The lesson says so.
6. The lost first step: the Host can drop a `session.step` sent before the first event. The app resends every 3 s as a workaround. The fix is PR #90, open, with its removal in draft PR #91.
7. Cosmetic: lesson 7's columns scroll sideways at 1440 px.

## 4. Choices made while Steve slept

1. App packages come from the MMP.GasPumpSimulator lockfile, and `npm ci` ran. The PRD's free list named only Go modules. No new package was chosen.
2. The toy tour is lesson 0, outside the 11 graded lessons, with its own spec.
3. The client name check was built, overruling a builder, so lesson 10 teaches it correctly.
4. Hostile and stalled peers were treated as in scope for SSH. No Steve call was needed, since it only added checks.
5. The suite grew from 202 to 208 clauses, by its author: mutual TLS and the TLS 1.1 server role.

## 5. Open and leftover

| Item | State |
|---|---|
| PR #90, lost first step | Open and mergeable at last check. Builder suites pass. Merge main and run the gate first |
| PR #91, remove the resend | Draft. After #90 |
| Remote branches and worktrees | 51 `E:\dev\ns-*` folders and 90 remote refs remain |
| `E:\dev\ns-s7-control`, `ns-fresh-*` | The house gate refused deletes of these. Remove them by hand if wanted |

Promises kept: the repo stayed private, nothing was published, and only made-up training keys were used. No third-party CE image was downloaded, and nothing was installed system-wide.

Lessons and corrections: `docs/learnings.md`.
