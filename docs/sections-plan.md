# MMP.NetworkSecurity: the 3-section plan

Owners: Richard (map, engine data, slices) and Nancy (screens). Decision owner: Steve. Reader before Steve: Jared. Date: 2026-11-07. Status: plan, with Steve's answers to Q1 to Q4 recorded on 2026-11-07. Slices build from it.

## The two changes I would make

1. **Keep the 12 lessons whole, in section 3, "Lessons".** The lessons, their tours and their attack runs keep their ids. Sections 1 and 2 add walks beside them. No lesson, tour, test id or acceptance clause is rewritten to make the split.
2. **Make W1b the AES walk inside section 2, with the long text on screen from its first slice.** Steve's requirement, "the long text is always visible", moves the long text forward from W2 into W1b.

## Conclusion

1. Steve asked for 3 sections: **Handshake**, **Cryptographic techniques** and **Lessons**. Section 3 is today's lesson list with its attack runs ("let's call 'attacks' lessons", Steve, 2026-11-07, through the lead). This plan places all 12 lessons (0 to 11), every mock tab, the 5 key flows (the wizard) and every attack run. Section 1 is the map.
2. Every lesson has a place: section 3 holds all 12. Each lesson also links to the walk in section 1 or 2 that shows its method, where one exists.
3. The engine registers 56 attack runs. The tours play 52 of them. 4 are in no tour (section 1.4).
4. The engine already holds every method the new walks need, with one exception: AES, SHA-256, HMAC, DES, the Diffie-Hellman group, X25519, Ed25519 and the TLS 1.3 key schedule are there. ECDSA is not, and Steve wants it, so its slice adds new engine code. Each new walk needs a new read-only walk type and a new route. No walk adds a field to W1a's frozen AES walk types (section 4).
5. A walk that runs on a session's own key gives that key away row by row. So each walk names its key. No new walk type in this plan runs on a session's own key: each runs on a public practice key or an RFC vector. W1a's block walk and the session trace keep their existing Show keys OFF rules (section 4).
6. The order is: the section shell, the AES walk with the long text (W1b), the attack index inside Lessons, the Handshake walk, then one technique walk per slice (section 5).
7. Kill condition: by 2026-11-27, 3 sections live, 12 of 12 lessons in Lessons, 56 of 56 registered attack runs reachable from the attack index, the AES walk in section 2 with the long text visible, and Steve has stepped through each section in the app (section 6).

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
| Elliptic curves: key agreement (ECDH, X25519) and signatures (ECDSA, Ed25519) | Techniques: elliptic curves | New. X25519 and Ed25519 run in the engine today. ECDSA does not (section 4). X25519 carries ECDH, so there is no ECDH walk on P-256 (Steve, Q2) |

### 1.3 The wizard and Security setup

| Item | Place | Why |
|---|---|---|
| Security setup page, its 15 types | Shared area, reached from the top bar, outside the 3 sections | A learner's keys serve lessons in every section |
| The 5 key flows: my-certificates, my-ssh, my-payment, my-login, my-lesson-keys | Shared area, as today | Same reason |
| The key vault page | Shared area | Same reason |
| The glossary page (#212) | Shared area, from Settings | It covers every section |

### 1.4 Attack runs

The engine registers **56** runs: 54 ids in `Labs.cs` and 2 in `Lesson11Timing.cs`. The live Host's `GET /api/lessons` and `/api/lessons/0` list the same 56 (Echo, 2026-11-07). The tours play **52**. All of them stay in their lessons, in section 3, and Lessons also gets an index of all 56 by kind (Steve, Q1). The kinds below are mine. Nancy's screen lines may rename them.

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

The index lists all 56. An entry for a run that a tour plays opens its tour step. An entry for one of the 4 runs in no tour opens its lesson's free play at the run's button (`attack-<attackId>`, which the free-play log draws for every registered run). Kinds for the 4: L0-flip-wire-byte, L2-flip-hmac-message and L2-flip-cmac-tag change bytes on the wire. L10-wrong-role asks for what was never granted. The kill condition counts 56. The index reads the registry from `GET /api/lessons`, so a run added later appears with no edit to the index.

The 5 "Switch to the eavesdropper view" try-its and lesson 7's "Run both handshakes" are views and runs, not attacks. They stay in their lessons.

## 2. Screens (Nancy)

Nancy's screen lines, 2026-11-07, with her update for Steve's answers. Plan only.

1. **Section switch.** A segmented switch at the left of the top bar, right after the brand: Handshake / Techniques / Lessons. It takes the place of Tour / Free play, and the mode becomes a smaller control inside the section. The bar keeps its one row: at 1280 the 3 labels cost about the width the mode switch frees. The rail lists the current section only:
   - Handshake: its walks (the wire and the eavesdropper view, the TLS 1.3 messages and key schedule, the certificate chain).
   - Techniques: AES, HMAC and chain, Feistel, Diffie-Hellman, X25519, Ed25519, ECDSA P-256. One item each. X25519 is the only elliptic-curve key-agreement item. Both signature families stay.
   - Lessons: today's 12 lessons, numbered as now, and one more item at the bottom, "Attack runs".
2. **R1, "the long text is always visible".** A pinned strip across the top of the workspace in Techniques, above the walk root. It shows one line of the long cleartext, mono, with the current block highlighted. It scrolls sideways, and the walk's chosen block stays in view. It stays while the learner moves between the Techniques items. A walk that shows a value derived from the text draws a link line from the strip to its grid. Height 44 px, so 1280 x 640 still fits the walk. It mounts outside `walk-root`, so the walk's clip cannot cut it. It reads the rows of `POST /api/walk/aes/long-text`, and the typed-block route feeds the walk's text box. Both routes stay open with Show keys off, so the strip shows with Show keys off too.
3. **Attack runs (the index, Steve's Q1).** "Attack runs" opens an index of all 56 runs grouped by kind. Each row names the attack, its lesson, and the check that catches it. The group labels on screen are Nancy's: tamper, replay, downgrade, swapped key or identity, nonce reuse, length extension, timing, token misuse. Slice P3 fixes how section 1.4's kinds map to these labels. A click on a row opens that lesson with the attack run: the normal run beside the attacked run, the changed message diffed in Message bytes with changed bytes lit, and the catching check under both, pass on the left and fail on the right. Back returns to the index with the row kept. This needs a new two-run layout: 2 sessions on one screen. The Both view does not do it, because Both shows one session's Endpoints and Eavesdropper diagrams (`ux-design.md`, "Both (split diagram)"). The nearest piece to reuse is lesson 7's "Old vs new race": 2 diagrams side by side on one clock (`ux-design.md` section 6, item 6). Slice P3 builds the two-run layout from it. Each pane uses the diagram that #219 made fill its pane.

   Group labels for section 1.4's kinds that Nancy's 8 labels do not name: "Ask for what was never granted" (L6-ask-past-key, L8-refused-tunnel, L10-ungranted-capability, L10-wrong-role) gets a ninth label, "never granted". "Time or freshness" (L4-expired-cert, L10-expired-token, L10-unissued-challenge) gets a tenth label, "expired or stale". P3 may merge labels, but no run goes without a group.
4. **Security setup, wizard, vault, glossary.** A shared area outside the 3 sections, reached from the top bar (Security setup) and from Settings (Glossary). Each replaces the workspace and keeps the bar, as today.
5. **Shell changes.** `workspace` and `walk-root` stay. Techniques adds the pinned strip as a sibling above `walk-root` inside `workspace`. `overlay-layer` is unchanged. The rail component takes the section as a prop. The Endpoints / Eavesdropper / Both views stay, unchanged. An attack run from the index opens in the new two-run layout (item 3), not in the Both view.
6. **Links.** Each lesson links to its walk (section 1.1), and each walk links back to its lessons.

Nancy's 2 screen questions are in section 8 as Q3 and Q4. Steve answered A to both: the pinned strip, and both runs side by side.

## 3. What moves and what is new

| Item | Moves or new | Change |
|---|---|---|
| Lesson rail | Moves | Becomes section 3, Lessons. Lesson numbers and ids unchanged |
| Tours, tour steps, try-its | Stay | No text or id change |
| The 56 registered attack runs | Stay in tours and free play | `attacks.json` (new) with attack id, kind, tour step (or none), and the guard sentence. Content only. The check name and code come from `GET /api/lessons` |
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

So no new walk type in this plan runs on a session's own key: each runs on a public practice key or an RFC vector. W1a's block walk and the session trace keep their existing Show keys OFF rules, as the first and last rows show. A new walk on a session's own key is a later choice, and it needs the "OFF closes" column below.

| Walk | Engine piece it reads | Key it runs on | If on a session's key, OFF closes | New type (name for the program design to fix) | New route | Reference check |
|---|---|---|---|---|---|---|
| AES block, key schedule, field (W1b) | `AesKey.Walk.cs` | The run's key at 128 bits, a practice key at 192 and 256, a public practice key for typed text | The whole block walk (W1a's rule) | None. W1a's types | W1a's routes, `/api/walk/aes/typed-block` | W1a's clauses |
| The long text (R1) | `Lesson01Aes.Pad`, `Modes` | Public practice key and IV | Not applicable | `AesLongTextView` (built on `feat/w1b-aes-walk`) | `/api/walk/aes/long-text` | BCL AES on the same blocks |
| SHA-256 | `Sha256Hash` | No key | Not applicable | `Sha256Walk` (padding, message schedule, 64 rounds per block) | `/api/walk/sha256` | FIPS 180-4 examples |
| HMAC | `Hmac` | RFC 4231 vector keys | K, K xor ipad, K xor opad, the inner and outer states | `HmacWalk` (inner and outer pass) | `/api/walk/hmac` | RFC 4231 HMAC vectors |
| The chain | `NetSec.Vault/AuditChain.cs`, the vault's hash-linked audit rows. Lesson 2 holds no chain code | A fixture chain built by `AuditChain` from a public seed. The learner's own audit log is a later choice | Not applicable to the fixture. `AuditChain.HashOf` covers prev_hash, seq, at, caller, op and name, so a real row holds no key bytes | `SealChainWalk`, in the Host, because the vault is not in Core and Core cannot reference it | `/api/walk/seal-chain` | Recompute each link with BCL SHA-256 |
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

The attack index needs no engine data: `run-attack` already plays each run, and each run's check is already a trace event. Its content is `app/src/attacks.json` (P3, content half).

**The two-run layout needs no engine change (checked 2026-11-07).**
1. Lesson 7's race is one session with two protocol streams, split by `protocolOf` in `lab.ts` (`raceStats`). It is not two sessions. So the two-run layout reuses the race's screen shape, and the data pairing is new app code.
2. An attack is a fork: the Host reruns the whole lesson with the parent's seed and the attack's plan (`Program.cs`, `Attack`), and sends `session.forked` with `parentId`. The parent run stays in the store's `ui.sessions`. So both runs already exist side by side.
3. Every trace frame carries `streamId` and `streamSeq` (`Trace.cs`, the JSON writer). The two runs pair event by event on that key until the attack changes the run. The app gap: `host.ts` keeps `streamId` and drops `streamSeq`. P3's screen half adds it.
4. A flip-byte attack changes bytes in one message, so Message bytes diffs the two events with one key. A scenario attack changes the run's options, so its pairs end where the runs part, and the screen marks that point.
5. One clock for both panes is app code: the race steps one session, and the two-run layout steps two by the paired key.

## 5. Slices and the work they change

| Slice | Builds | Closing check | Changes existing work |
|---|---|---|---|
| P0 | This plan, Jared's read, Steve's answers to section 8 | Steve's answers recorded in this file | None |
| P1 section shell | The 3-section switch, with today's rail as Lessons, from Nancy's lines. No engine change | The specs pass with every lesson reachable. 12 of 12 lessons in Lessons | Builds on Nancy's shell (#196). The ux-refresh slices stay as planned |
| P2 = W1b | The AES walk in section 2, chapter 1, with the long text (R1). Engine half built on `feat/w1b-aes-walk` | W1b's clauses, plus a long-text clause | **W1b becomes the AES walk in section 2.** It takes W2's long text forward. W2 keeps the S-box build, tap-a-byte and the flip spread |
| Stop: show Steve | Steve steps through section 2 in the app | His reaction in `docs/learnings.md` | Unchanged stop from `walkthrough-design.md` |
| P3 attack index | `attacks.json`, the list by kind inside Lessons, each entry opening its tour step or its free-play button. The two-run layout, built from lesson 7's race (section 2, item 3; Steve, Q4) | 56 of 56 registered runs reachable, each plays its run and shows its check | None to the tours. The race layout becomes shared by lesson 7 and the index |
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
3. 56 of 56 registered attack runs (the count `GET /api/lessons` and `/api/lessons/0` give) are reachable from the attack index, and each plays its run.
4. The AES walk (W1b) runs in section 2, and the long text is on screen on every technique tab that exists.
5. Steve has stepped through each section in the app and reacted.

A progress report states these 5 counts. It does not substitute the fact that building continued.

## 7. Non-goals

1. No new lesson and no tour rewrite. Sections group what exists.
2. No new crypto in the engine, except ECDSA on P-256 in slice P8b, which Steve asked for. Every other walk reads engine code that already exists. DES runs today only in tests.
3. No change to W1a's frozen walk types.
4. No change to the acceptance clause ids.
5. No handshake offers P-256 or ECDSA. That code is walk-only.
6. No new walk type in this plan runs on a session's own key. W1a's block walk and the session trace keep their existing Show keys OFF rules (section 4).

## 8. Questions for Steve

| Id | Question | Option A | Option B | My pick |
|---|---|---|---|---|
| Q1 | Lessons: list the attack runs a second way? | Lessons also gets an index of the attack runs, grouped by kind. Each entry opens the lesson at the step that plays it | No index. Each run stays only in its tour step | **A.** It answers "how do things break" in one place, and no tour or clause changes. **Steve: A** |
| Q2 | Key agreement on elliptic curves: is X25519 enough, or do you also want ECDH on P-256? | X25519 carries ECDH. P-256 appears only in the ECDSA walk | Also an ECDH walk on P-256, on the same new P-256 code | **A.** X25519 is ECDH on Curve25519, and the lessons run it today. B adds a walk on code no lesson runs. **Steve: A** |

Nancy's 2 screen questions (section 2), answered by Steve:

| Id | Question | Option A | Option B | Nancy's pick, and Steve's answer |
|---|---|---|---|---|
| Q3 | Where does the long text live in Techniques? | A pinned strip above the walk, one line, scrolling sideways | A side column, wrapped, about 280 px wide | **A.** The walk needs the width at 1280, and one line keeps byte offsets readable. **Steve: A** |
| Q4 | When a learner opens an attack run from the index, what shows first? | The normal run and the attacked run side by side. This needs a new two-run layout, built from lesson 7's race layout | The attacked run alone, with a "show the normal run" toggle. This reuses today's one-run screen | **A.** The difference is the lesson. The cost is one new layout in P3, built on a layout the app already has. **Steve: A** |

**Answered (2026-11-07, Steve, through the lead):**
1. Elliptic-curve methods mean both key agreement (ECDH, X25519) and signatures (ECDSA, Ed25519). Both go in section 2.
2. W1b becomes the AES walk inside section 2, and it goes before V4's certificate file path.
3. Section 3 is named Lessons ("let's call 'attacks' lessons"). Today's lesson list, with its attack runs, becomes section 3. This answers the old question about lessons 6, 8, 9 and 10: they stay in Lessons with the rest. It also settles lesson numbers: Lessons keeps 0 to 11.
4. Q1: A. Lessons gets an index of the attack runs by kind. The index lists all 56 registered runs, the live count from `GET /api/lessons`.
5. Q2: A. X25519 is enough for key agreement. There is no ECDH walk on P-256. ECDSA keeps P-256 (slice P8b).
6. Q3: A. The long text is a pinned one-line strip above the walk in Techniques. The W1b screens use it.
7. Q4: A. An attack run from the index opens with the normal run and the attacked run side by side. P3 builds the two-run layout from lesson 7's race.

## 9. Prior art

Checked: `docs/walkthrough-design.md` (the AES pilot, section 6 slices, section 9 open list), `docs/ux-refresh-plan.md` (the shell and the walk root), and the 12 tour files for the attack runs. The structure follows a course table of contents grouped by subject, which the app already half has in its lesson rail. I did not consult the system-design catalog: this is a screen grouping over existing data, with no load, storage or service question.

Jared read 23df25c (same-vendor fresh read). His anchor: a git grep on origin/main for every engine piece in section 4, an id diff of the attack runs against `Labs.cs` and `Lesson11Timing.cs`, and the source text of RFC 6979 and FIPS 186-5. His 3 blockers (ECDSA k, Show keys OFF per walk, 56 engine runs) and 3 notes are folded in above.

## Disposition

Jared passed this plan (35e95ce). Steve answered Q1 to Q4 in section 8 on 2026-11-07. The lead starts P1. Nancy builds the W1b screens after SC lands.
