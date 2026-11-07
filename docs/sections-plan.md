# MMP.NetworkSecurity: the 3-section plan

Owners: Richard (map, engine data, slices) and Nancy (screens). Decision owner: Steve. Reader before Steve: Jared. Date: 2026-11-07. Status: plan only. No code comes from this document until Steve answers section 8.

## The two changes I would make

1. **Keep the 12 lessons whole, in section 3, "Lessons".** The lessons, their tours and their attack runs keep their ids. Sections 1 and 2 add walks beside them. No lesson, tour, test id or acceptance clause is rewritten to make the split.
2. **Make W1b the AES walk inside section 2, with the long text on screen from its first slice.** Steve's requirement, "the long text is always visible", moves the long text forward from W2 into W1b.

## Conclusion

1. Steve asked for 3 sections: **Handshake**, **Cryptographic techniques** and **Lessons**. Section 3 is today's lesson list with its attack runs ("let's call 'attacks' lessons", Steve, 2026-11-07, through the lead). This plan places all 12 lessons (0 to 11), every mock tab, the 5 key flows (the wizard) and every attack run. Section 1 is the map.
2. Every lesson has a place: section 3 holds all 12. Each lesson also links to the walk in section 1 or 2 that shows its method, where one exists.
3. The engine registers 56 attack runs. The tours play 52 of them. 4 are in no tour (section 1.4).
4. The engine already holds every method the new walks need, with one exception: AES, SHA-256, HMAC, DES, the Diffie-Hellman group, X25519, Ed25519 and the TLS 1.3 key schedule are there. ECDSA is not, and Steve wants it, so its slice adds new engine code. Each new walk needs a new read-only walk type and a new route. No walk adds a field to W1a's frozen AES walk types (section 4).
5. A walk that runs on a session's own key gives that key away row by row. So each walk names its key, and the first slices run only on public practice keys and RFC vectors (section 4).
6. The order is: the section shell, the AES walk with the long text (W1b), the attack index inside Lessons, the Handshake walk, then one technique walk per slice (section 5).
7. Kill condition: by 2026-11-27, 3 sections live, 12 of 12 lessons in Lessons, 52 of 52 tour attack runs reachable, the AES walk in section 2 with the long text visible, and Steve has stepped through each section in the app (section 6).

## Requirements

| Id | Requirement | Source |
|---|---|---|
| R1 | **The long text is always visible.** In section 2, the long cleartext stays on screen while the learner moves between the technique tabs. | Steve's routine sentence, as the lead relayed it |
| R2 | The app has 3 sections: Handshake, Cryptographic techniques, Lessons. | Steve, 2026-11-07, through the lead |
| R3 | Section 2 holds AES as in the mock (block, key schedule, finite field, HMAC and the chain), Feistel and Diffie-Hellman each on its own, and the elliptic-curve methods: key agreement (ECDH, X25519) and signatures (ECDSA, Ed25519). | Steve, 2026-11-07, through the lead |
| R4 | Section 3, Lessons, holds today's lessons with their attack runs: how things break and how to guard against it. | Steve |
| R5 | Every walk draws real engine data. The app runs no math (the real data rule, `walkthrough-design.md` section 3). | Existing rule |
| R6 | No walk adds a field to W1a's frozen walk types. A walk that needs more data gets its own type and route. | `walkthrough-design.md` section 9 |

## 1. The map

### 1.1 Lessons

All 12 lessons go in section 3, Lessons, with their numbers kept. The last column is the walk each lesson links to.

| Lesson | Title (first tour step) | Section | Links to |
|---|---|---|---|
| 0 | A pipe with two ends | Lessons | Handshake: the wire and the eavesdropper view |
| 1 | Why we lock data | Lessons | Techniques: AES |
| 2 | Why a message needs a seal | Lessons | Techniques: HMAC and the chain |
| 3 | Strangers need a shared key | Lessons | Techniques: Diffie-Hellman and elliptic curves (X25519) |
| 4 | A secret shared with whom? | Lessons | Handshake: the certificate chain |
| 5 | One handshake, three jobs | Lessons | Handshake: TLS 1.3 messages and key schedule |
| 6 | One key for every sale | Lessons | None yet. DUKPT has no walk in this plan |
| 7 | An old device meets a new world | Lessons | Handshake: TLS 1.1 beside TLS 1.3 |
| 8 | SSH: two proofs, no certificate authority | Lessons | Techniques: Diffie-Hellman (lesson 8's legacy exchange runs `DhGroup14`) |
| 9 | An old device and a new server | Lessons | Handshake |
| 10 | Who are you, and what may you do? | Lessons | Techniques: Ed25519 signatures |
| 11 | A compare that tells on you | Lessons | None. The whole lesson is an attack and its guard |

### 1.2 Mock tabs and walk parts

| Item | Section | State today |
|---|---|---|
| AES: the block, chapter 1 | Techniques: AES | W1a engine merged (#178). W1b engine half on `feat/w1b-aes-walk`. Screens not started |
| AES: the key schedule | Techniques: AES | W1a engine merged. Screen in W1b |
| AES: the finite field | Techniques: AES | W1a engine merged. Screen in W1b |
| AES: modes, chapter 2 (ECB, CBC, GCM) | Techniques: AES | W1c, after Steve's look at W1b |
| The long text and the picture | Techniques, on every tab (R1) | Was W2. Moved into W1b. Route built on `feat/w1b-aes-walk` |
| HMAC tab: SHA-256, the HMAC steps, the chain, the daily seal | Techniques: HMAC and the chain | Open list, no design. The daily seal has no engine code (section 4) |
| Feistel tab | Techniques: Feistel | Open list, no design |
| Diffie-Hellman tab | Techniques: Diffie-Hellman | Open list (W3), no design |
| Elliptic curves: key agreement (ECDH, X25519) and signatures (ECDSA, Ed25519) | Techniques: elliptic curves | New. X25519 and Ed25519 run in the engine today. ECDSA does not (section 4). ECDH on P-256 is question Q2 |

### 1.3 The wizard and Security setup

| Item | Place | Why |
|---|---|---|
| Security setup page, its 15 types | Shared area, reached from the top bar, outside the 3 sections | A learner's keys serve lessons in every section |
| The 5 key flows: my-certificates, my-ssh, my-payment, my-login, my-lesson-keys | Shared area, as today | Same reason |
| The key vault page | Shared area | Same reason |
| The glossary page (#212) | Shared area, from Settings | It covers every section |

### 1.4 Attack runs

The engine registers **56** runs: 54 ids in `Labs.cs` and 2 in `Lesson11Timing.cs`. The tours play **52**. All of them stay in their lessons, in section 3. Q1 asks whether Lessons also gets an index by kind. The kinds below are mine. Nancy's screen lines may rename them.

| Kind | Runs | Count |
|---|---|---|
| Change bytes on the wire: the check catches it | L1-flip-gcm, L1-flip-cbc, L2-flip-hash-message, L2-flip-hmac-tag, L2-flip-cmac-message, L3-flip-mlkem-ciphertext, L4-flip-cert-byte, L4-flip-cert-verify, L5-flip-mlkem-ciphertext, L5-flip-record-byte, L5-flip-finished, L5-flip-record-length, L6-flip-pin-block, L7-flip-record, L8-flip-exchange-signature, L8-flip-packet, L8-legacy-flip-signature, L9-tamper-hop1, L9-tamper-hop2, L9-flip-pin-block, L10-corrupt-client-cert, L10-change-token-claim | 22 |
| Swap a key or an identity | L3-swap-server-share, L4-unknown-ca, L4-wrong-name, L5-replace-key-share, L8-zero-share, L8-change-host-key, L8-wrong-user-key, L10-remove-client-cert, L10-wrong-client-name, L10-unknown-device, L10-wrong-audience, L10-stolen-token | 12 |
| Replay | L6-replay-sale, L10-replay-challenge, L10-replay-proof | 3 |
| Misuse a mode or a nonce | L1-use-ecb, L1-reuse-nonce | 2 |
| Forge a seal by length extension | L2-extend-keyed-hash, L2-extend-hmac | 2 |
| Downgrade or an old protocol | L7-downgrade, L7-modern-server | 2 |
| Time or freshness | L4-expired-cert, L10-expired-token, L10-unissued-challenge | 3 |
| Ask for what was never granted | L6-ask-past-key, L8-refused-tunnel, L10-ungranted-capability | 3 |
| Side channel | L11-guess-leaky, L11-guess-constant-time | 2 |
| Not settled: L5-clear-close-notify (a cut stream, not a byte change) | Placed under "Change bytes" for now | 1 |
| **Tour runs, total** | | **52** |
| In the engine, in no tour | L0-flip-wire-byte, L2-flip-hmac-message, L2-flip-cmac-tag, L10-wrong-role | 4 |
| **Engine runs, total** | | **56** |

The 4 runs in no tour stay out of the index in this plan's first step. The kill condition counts the 52 tour runs. L10-wrong-role appears in no test and no spec either. That is a test gap for Echo, and it is outside this plan.

The 5 "Switch to the eavesdropper view" try-its and lesson 7's "Run both handshakes" are views and runs, not attacks. They stay in their lessons.

## 2. Screens (Nancy)

Nancy writes this section. Her lines come after Steve's clipping fix. Until they arrive, these are my proposals, for her to replace:

1. **Section switch:** 3 tabs at the top of the left rail: Handshake, Techniques, Lessons. Lessons shows today's lesson rail, with the numbers kept.
2. **R1, the long text:** a strip that stays in section 2's layout on every technique tab, above the walk. Each walk names which bytes of the long text it is using.
3. **Attack index (if Q1 is A):** inside Lessons, a list grouped by kind (section 1.4). Each entry opens its lesson at the tour step that plays the run.
4. **Links:** each lesson has a link to its walk (section 1.1), and each walk links back to its lessons.
5. **Security setup, the wizard, the vault and the glossary:** in the shared area, reached from the top bar, as today.

## 3. What moves and what is new

| Item | Moves or new | Change |
|---|---|---|
| Lesson rail | Moves | Becomes section 3, Lessons. Lesson numbers and ids unchanged |
| Tours, tour steps, try-its | Stay | No text or id change |
| The 52 tour attack runs | Stay in tours | If Q1 is A: `attacks.json` (new) with attack id, kind, lesson, tour step, the check that catches it, and the guard sentence. Content only |
| AES walk (W1b) | New screens in section 2 | Adds the long text (was W2) |
| HMAC and chain walk | New | Section 2 |
| Feistel walk | New | Section 2, on the engine's DES |
| Diffie-Hellman walk | New | Section 2 |
| Elliptic-curve walks | New | Section 2: X25519 (ECDH on Curve25519) and Ed25519 first, then ECDSA on P-256 with new engine code |
| Handshake walk | New | Section 1: the TLS 1.3 messages, the key schedule, and the certificate chain |
| Security setup, wizard, vault, glossary | Stay | Shared area |

## 4. Engine data for each new walk (frozen-shape rule)

Each walk gets its own immutable walk type in Core (C# 3, both builds) and its own read-only Host route under `/api/walk/`. No walk adds a field to `AesStep`, `AesBlockWalk` or any other W1a type.

**The key decides what Show keys OFF closes.** W1a's typed-text walks are safe with Show keys OFF because they run on a public practice key (`walkthrough-design.md` section 3.5). The walks below are different: each shows values that give away the key it runs on. A Diffie-Hellman square-and-multiply row, or an X25519 ladder row with its swap bit, shows one bit of the private scalar. An ECDSA k gives the private key: d = (s·k − z)/r. The Ed25519 r and secret scalar do the same. HMAC's K xor ipad gives K. DES subkeys give the key.

So this plan's walks run only on a public practice key or an RFC vector. A walk on a session's own key is a later choice, and it needs the "OFF closes" column below.

| Walk | Engine piece it reads | Key it runs on | If on a session's key, OFF closes | New type (name for the program design to fix) | New route | Reference check |
|---|---|---|---|---|---|---|
| AES block, key schedule, field (W1b) | `AesKey.Walk.cs` | The run's key at 128 bits, a practice key at 192 and 256, a public practice key for typed text | The whole block walk (W1a's rule) | None. W1a's types | W1a's routes, `/api/walk/aes/typed-block` | W1a's clauses |
| The long text (R1) | `Lesson01Aes.Pad`, `Modes` | Public practice key and IV | Not applicable | `AesLongTextView` (built on `feat/w1b-aes-walk`) | `/api/walk/aes/long-text` | BCL AES on the same blocks |
| SHA-256 | `Sha256Hash` | No key | Not applicable | `Sha256Walk` (padding, message schedule, 64 rounds per block) | `/api/walk/sha256` | FIPS 180-4 examples |
| HMAC | `Hmac` | RFC 4231 vector keys | K, K xor ipad, K xor opad, the inner and outer states | `HmacWalk` (inner and outer pass) | `/api/walk/hmac` | RFC 4231 HMAC vectors |
| The chain | `NetSec.Vault/AuditChain.cs`, the vault's hash-linked audit rows. Lesson 2 holds no chain code | The vault's own rows | The program design checks whether a row holds key material. If one does, OFF closes that field | `SealChainWalk`, in the Host, because the vault is not in Core and Core cannot reference it | `/api/walk/seal-chain` | Recompute each link with BCL SHA-256 |
| The daily seal | **No engine code exists.** The mock shows it, and nothing in `src/` makes one | Not planned | Not planned | Not planned | Not planned | Out of this plan until Steve says what the daily seal shows. It would be new engine code, which section 7 rules out |
| Feistel | `Des.cs`, which runs only inside `TdesKey`, and only tests call that. No lesson runs DES | FIPS 46-3 or SP 800-17 known-answer keys | Every subkey and the key | `DesWalk` (initial permutation, 16 rounds of left and right halves, expansion, S-boxes, permutation, subkeys) | `/api/walk/des` | FIPS 46-3 or SP 800-17 known answers |
| Diffie-Hellman | `DhGroup14`, `BigUInt.ModPow`. Lesson 8's legacy exchange runs `DhGroup14` (`SshClientRules.cs`) | A public practice exponent, on a small prime and on group 14 | Every square-and-multiply row and the private exponent | `DhWalk` (square-and-multiply rows; a small prime for reading, group 14 for the real run). The engine computes the small-prime run too. The app computes nothing (R5) | `/api/walk/dh` | Python `pow()`, as `dh-group14-rfc3526.nsv` does today |
| X25519 | `X25519`, `Montgomery` | RFC 7748 section 5.2 vector scalars | Every ladder row, each swap bit, and the scalar | `X25519Walk` (the ladder: one row per bit, the swap, the 4 field values) | `/api/walk/x25519` | RFC 7748 section 5.2 vectors |
| Ed25519 signature | `Ed25519` | RFC 8032 section 7.1 vector keys | r, the secret scalar, and the seed | `Ed25519Walk` (r, R, k, S, then verify) | `/api/walk/ed25519` | RFC 8032 section 7.1 vectors |
| ECDSA signature on P-256 | **No engine code exists.** The engine has no P-256 and no ECDSA | RFC 6979 section A.2.5 P-256 vector keys | Not applicable: walk-only, never a session key | New Core code first: P-256 point arithmetic, ECDSA sign and verify with RFC 6979 deterministic k, then `EcdsaWalk` | `/api/walk/ecdsa` | RFC 6979 A.2.5: the engine's R and S equal the vector values. OpenSSL signs with a random k, so OpenSSL referees by cross-verify: OpenSSL verifies the engine's signature, and the engine verifies OpenSSL's. Spike before sign-off |
| TLS 1.3 key schedule | `Tls13KeySchedule` | The RFC 8448 section 3 trace | The shared secret and every derived secret | `Tls13ScheduleWalk` (each Extract and Derive-Secret, with its label and transcript hash) | `/api/walk/tls13/schedule` | RFC 8448 section 3 trace, as `tls13-rfc8448.nsv` does today |
| TLS 1.3 messages and the chain | Trace events `tls.handshake.sent` and `.received`, lesson 4's certificate parse | The session's own run | As today: Show keys OFF already governs the trace | None. The trace already holds them | Existing session routes | Lesson 5's and lesson 4's clauses |

**ECDSA constraints (slice P8b):**
1. The deterministic k comes from RFC 6979. FIPS 186-5 approves it: "known as deterministic ECDSA is also approved and specified in IETF RFC 6979". A random k would make the walk impossible to repeat and to match a fixed vector.
2. `NetSec.Core.NetCF` compiles `..\NetSec.Core\**\*.cs`. So the P-256 code must build for CF 3.5 and pass the CE audit.
3. The P-256 code is walk-only. No handshake ever offers it (non-goal 5).
4. It is not constant-time. The walk says so, and links to lesson 11, which teaches timing leaks.

The attack index needs no engine data: `run-attack` already plays each run, and each run's check is already a trace event.

## 5. Slices and the work they change

| Slice | Builds | Closing check | Changes existing work |
|---|---|---|---|
| P0 | This plan, Jared's read, Steve's answers to section 8 | Steve's answers recorded in this file | None |
| P1 section shell | The 3-section switch, with today's rail as Lessons, from Nancy's lines. No engine change | The specs pass with every lesson reachable. 12 of 12 lessons in Lessons | Builds on Nancy's shell (#196). The ux-refresh slices stay as planned |
| P2 = W1b | The AES walk in section 2, chapter 1, with the long text (R1). Engine half built on `feat/w1b-aes-walk` | W1b's clauses, plus a long-text clause | **W1b becomes the AES walk in section 2.** It takes W2's long text forward. W2 keeps the S-box build, tap-a-byte and the flip spread |
| Stop: show Steve | Steve steps through section 2 in the app | His reaction in `docs/learnings.md` | Unchanged stop from `walkthrough-design.md` |
| P3 attack index (if Q1 is A) | `attacks.json`, the list by kind inside Lessons, each entry opening its tour step | 52 of 52 tour runs reachable, each plays its run and shows its check | None to the tours |
| P4 Handshake walk | The TLS 1.3 message walk, the key schedule walk, the chain view | RFC 8448 values, lesson 4 and 5 clauses | Takes **W4** (lesson 5 record walk) and the lesson 4 half of **W3** |
| P5 W1c | Chapter 2 modes, unchanged | W1c's clauses | Unchanged, now inside section 2 |
| P6 HMAC and chain | `Sha256Walk`, `HmacWalk`, `SealChainWalk` | FIPS 180-4 and RFC 4231 | Takes lesson 2 from **W5** |
| P7 Diffie-Hellman | `DhWalk`. Its live run in the course is lesson 8's legacy exchange | `pow()` references | Takes the lesson 3 half of **W3** |
| P8 Elliptic curves, engine today | `X25519Walk` and `Ed25519Walk` | RFC 7748, RFC 8032 | New |
| P8b ECDSA | New Core code: P-256, ECDSA sign and verify with RFC 6979 k, then `EcdsaWalk`. Spike first | RFC 6979 A.2.5 values, and OpenSSL cross-verify both ways | New. The one slice that adds crypto to the engine |
| P9 Feistel | `DesWalk` | DES known answers | New |

The kill condition in section 6 covers P0 to P3. P4 onward is a second plan step, which Steve orders after his look.

## 6. Kill condition

This plan's first step ends when all of these hold, by **2026-11-27**:

1. 3 of 3 sections are live in the app.
2. 12 of 12 lessons are in the Lessons section, with their numbers kept.
3. If Q1 is A: 52 of 52 tour attack runs are reachable from the attack index, and each plays its run. If Q1 is B: 52 of 52 still play from their tour steps.
4. The AES walk (W1b) runs in section 2, and the long text is on screen on every technique tab that exists.
5. Steve has stepped through each section in the app and reacted.

A progress report states these 5 counts. It does not substitute the fact that building continued.

## 7. Non-goals

1. No new lesson and no tour rewrite. Sections group what exists.
2. No new crypto in the engine, except ECDSA on P-256 in slice P8b, which Steve asked for. Every other walk reads engine code that already exists. DES runs today only in tests.
3. No change to W1a's frozen walk types.
4. No change to the acceptance clause ids.
5. No handshake offers P-256 or ECDSA. That code is walk-only.
6. No walk in this plan runs on a session's own key (section 4).

## 8. Questions for Steve

| Id | Question | Option A | Option B | My pick |
|---|---|---|---|---|
| Q1 | Lessons: list the attack runs a second way? | Lessons also gets an index of the 52 tour runs, grouped by kind. Each entry opens the lesson at the step that plays it | No index. Each run stays only in its tour step | **A.** It answers "how do things break" in one place, and no tour or clause changes |
| Q2 | Key agreement on elliptic curves: is X25519 enough, or do you also want ECDH on P-256? | X25519 carries ECDH. P-256 appears only in the ECDSA walk | Also an ECDH walk on P-256, on the same new P-256 code | **A.** X25519 is ECDH on Curve25519, and the lessons run it today. B adds a walk on code no lesson runs |

Nancy may add 1 screen question here.

**Answered (2026-11-07, Steve, through the lead):**
1. Elliptic-curve methods mean both key agreement (ECDH, X25519) and signatures (ECDSA, Ed25519). Both go in section 2.
2. W1b becomes the AES walk inside section 2, and it goes before V4's certificate file path.
3. Section 3 is named Lessons ("let's call 'attacks' lessons"). Today's lesson list, with its attack runs, becomes section 3. This answers the old question about lessons 6, 8, 9 and 10: they stay in Lessons with the rest. It also settles lesson numbers: Lessons keeps 0 to 11.

## 9. Prior art

Checked: `docs/walkthrough-design.md` (the AES pilot, section 6 slices, section 9 open list), `docs/ux-refresh-plan.md` (the shell and the walk root), and the 12 tour files for the attack runs. The structure follows a course table of contents grouped by subject, which the app already half has in its lesson rail. I did not consult the system-design catalog: this is a screen grouping over existing data, with no load, storage or service question.

Jared read 23df25c (same-vendor fresh read). His anchor: a git grep on origin/main for every engine piece in section 4, an id diff of the attack runs against `Labs.cs` and `Lesson11Timing.cs`, and the source text of RFC 6979 and FIPS 186-5. His 3 blockers (ECDSA k, Show keys OFF per walk, 56 engine runs) and 3 notes are folded in above.

## Disposition

Plan only. Jared reads this head. Steve answers section 8. Then the lead starts P1.
