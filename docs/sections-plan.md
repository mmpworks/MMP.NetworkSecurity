# MMP.NetworkSecurity: the 3-section plan

Owners: Richard (map, engine data, slices) and Nancy (screens). Decision owner: Steve. Reader before Steve: Jared. Date: 2026-11-07. Status: plan only. No code comes from this document until Steve answers section 8.

## The two changes I would make

1. **Put every lesson in one of 3 sections, and keep the lessons whole.** The 12 lessons, their tours and their 52 attack runs keep their ids. Sections group them. No lesson, tour, test id or acceptance clause is rewritten to make the split.
2. **Make W1b the AES walk inside section 2, with the long text on screen from its first slice.** Steve's requirement, "the long text is always visible", moves the long text forward from W2 into W1b.

## Conclusion

1. Steve asked for 3 sections: **Handshake**, **Cryptographic techniques** and **Attacks**. This plan places all 12 lessons (0 to 11), every mock tab, the 5 key flows (the wizard) and all 52 attack runs. Section 1 is the map.
2. 4 lessons have no clean place: lessons 6, 8, 9 and 10. Section 8 asks Steve 1 question about them, with my pick.
3. The engine already holds every method the new walks need: AES, SHA-256, HMAC, DES, the Diffie-Hellman group, X25519, Ed25519 and the TLS 1.3 key schedule. Each new walk needs a new read-only walk type and a new route. No walk adds a field to W1a's frozen AES walk types (section 4).
4. The order is: the section shell, the AES walk with the long text (W1b), the Attacks index, the Handshake walk, then one technique walk per slice (section 5).
5. Kill condition: by 2026-11-27, 3 sections live, 12 of 12 lessons placed, 52 of 52 attack runs reachable from Attacks, the AES walk in section 2 with the long text visible, and Steve has stepped through each section in the app (section 6).

## Requirements

| Id | Requirement | Source |
|---|---|---|
| R1 | **The long text is always visible.** In section 2, the long cleartext stays on screen while the learner moves between the technique tabs. | Steve's routine sentence, as the lead relayed it |
| R2 | The app has 3 sections: Handshake, Cryptographic techniques, Attacks. | Steve |
| R3 | Section 2 holds AES as in the mock (block, key schedule, finite field, HMAC and the chain), Feistel and Diffie-Hellman each on its own, and the elliptic-curve methods. | Steve |
| R4 | Section 3 shows how things break and how to guard against it, built from today's tour attack runs. | Steve |
| R5 | Every walk draws real engine data. The app runs no math (the real data rule, `walkthrough-design.md` section 3). | Existing rule |
| R6 | No walk adds a field to W1a's frozen walk types. A walk that needs more data gets its own type and route. | `walkthrough-design.md` section 9 |

## 1. The map

### 1.1 Lessons

| Lesson | Title (first tour step) | Section | Why |
|---|---|---|---|
| 0 | A pipe with two ends | Handshake, as its first step | It shows the wire and the eavesdropper view, which every handshake builds on |
| 1 | Why we lock data | Techniques: AES | AES, its modes, and the ECB picture |
| 2 | Why a message needs a seal | Techniques: HMAC and the chain | SHA-256, length extension, HMAC, CMAC |
| 3 | Strangers need a shared key | Techniques: agree a key (DH and EC) | X25519 and ML-KEM agree a key |
| 4 | A secret shared with whom? | Handshake | Certificates and the chain to a trusted root |
| 5 | One handshake, three jobs | Handshake | The TLS 1.3 handshake, end to end |
| 6 | One key for every sale | **Question Q1** | DUKPT is a key scheme in a payment flow. It is neither a TLS handshake nor a method Steve named |
| 7 | An old device meets a new world | Handshake | The TLS 1.1 handshake beside TLS 1.3 |
| 8 | SSH: two proofs, no certificate authority | **Question Q1** | A handshake, but not the TLS chain Steve named |
| 9 | An old device and a new server | **Question Q1** | A bridge that chains SSH or TLS 1.1 to TLS 1.3, with DUKPT inside |
| 10 | Who are you, and what may you do? | **Question Q1** | Client proof after the handshake: certificates, a passkey-shaped login, tokens |
| 11 | A compare that tells on you | Attacks | A timing side channel. The whole lesson is an attack and its guard |

### 1.2 Mock tabs and walk parts

| Item | Section | State today |
|---|---|---|
| AES: the block, chapter 1 | Techniques: AES | W1a engine merged (#178). W1b screens not started |
| AES: the key schedule | Techniques: AES | W1a engine merged. Screen in W1b |
| AES: the finite field | Techniques: AES | W1a engine merged. Screen in W1b |
| AES: modes, chapter 2 (ECB, CBC, GCM) | Techniques: AES | W1c, after Steve's look at W1b |
| The long text and the picture | Techniques, on every tab (R1) | Was W2. Moves into W1b |
| HMAC tab: SHA-256, the HMAC steps, the chain, the daily seal | Techniques: HMAC and the chain | Open list, no design. The daily seal has no engine code (section 4) |
| Feistel tab | Techniques: Feistel | Open list, no design |
| Diffie-Hellman tab | Techniques: Diffie-Hellman | Open list (W3), no design |
| Elliptic curves: ECDH or X25519, and a signature | Techniques: elliptic curves | New. **Question Q2** for the signature |

### 1.3 The wizard and Security setup

| Item | Place | Why |
|---|---|---|
| Security setup page, its 15 types | Shared area, reached from the top bar, outside the 3 sections | A learner's keys serve lessons in every section |
| The 5 key flows: my-certificates, my-ssh, my-payment, my-login, my-lesson-keys | Shared area, as today | Same reason |
| The key vault page | Shared area | Same reason |
| The glossary page (#212) | Shared area, from Settings | It covers every section |

### 1.4 Attack runs

All 52 runs stay in their tour steps. The Attacks section indexes them by kind and plays the same runs (Q3 sets this). The kinds below are mine. Nancy's screen lines may rename them.

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
| **Questions:** L5-clear-close-notify (a cut stream, not a byte change) | Placed under "Change bytes" for now | 1 |
| **Total** | | **52** |

The 5 "Switch to the eavesdropper view" try-its and lesson 7's "Run both handshakes" are views and runs, not attacks. They stay in their lessons.

## 2. Screens (Nancy)

Nancy writes this section. Her lines are pending. Until they arrive, these are my proposals, for her to replace:

1. **Section switch:** 3 tabs at the top of the lesson rail. The rail lists only the current section's lessons, with their numbers kept.
2. **R1, the long text:** a strip that stays in section 2's layout on every technique tab, above the walk. Each walk names which bytes of the long text it is using.
3. **Attacks:** a list grouped by kind (section 1.4). One attack screen shows the normal run beside the attacked run, then the check that caught it, then the guard in one sentence.
4. **Security setup, the wizard, the vault and the glossary:** in the shared area, reached from the top bar, as today.

## 3. What moves and what is new

| Item | Moves or new | Change |
|---|---|---|
| Lesson rail | Moves | Grouped by section. Lesson numbers and ids unchanged |
| Tours, tour steps, try-its | Stay | No text or id change |
| The 52 attack runs | Stay in tours. New index | `attacks.json` (new): attack id, kind, lesson, the check that catches it, the guard sentence. Content only |
| AES walk (W1b) | New screens in section 2 | Adds the long text (was W2) |
| HMAC and chain walk | New | Section 2 |
| Feistel walk | New | Section 2, on the engine's DES |
| Diffie-Hellman walk | New | Section 2 |
| Elliptic-curve walks | New | Section 2: X25519, then a signature (Q2) |
| Handshake walk | New | Section 1: the TLS 1.3 messages, the key schedule, and the certificate chain |
| Security setup, wizard, vault, glossary | Stay | Shared area |

## 4. Engine data for each new walk (frozen-shape rule)

Each walk gets its own immutable walk type in Core (C# 3, both builds) and its own read-only Host route under `/api/walk/`. No walk adds a field to `AesStep`, `AesBlockWalk` or any other W1a type. Each walk honours Show keys OFF, as W1a does (`walkthrough-design.md` section 3.5).

| Walk | Engine piece it reads | New type (name for the program design to fix) | New route | Reference check |
|---|---|---|---|---|
| AES block, key schedule, field (W1b) | `AesKey.Walk.cs` | None. W1a's types | W1a's routes | W1a's clauses |
| The long text (R1) | `Lesson01Aes.MeasureBlocks`, `Modes` | `AesLongTextView` (already in `walkthrough-design.md` section 3.3) | `/api/walk/aes/long-text` | BCL AES on the same blocks |
| SHA-256 and HMAC | `Sha256Hash`, `Hmac` | `Sha256Walk` (padding, message schedule, 64 rounds per block), `HmacWalk` (inner and outer pass) | `/api/walk/sha256`, `/api/walk/hmac` | FIPS 180-4 examples, RFC 4231 HMAC vectors |
| The chain | `NetSec.Vault/AuditChain.cs`, the vault's hash-linked audit rows. Lesson 2 holds no chain code | `SealChainWalk`, in the Host, because the vault is not in Core and Core cannot reference it | `/api/walk/seal-chain` | Recompute each link with BCL SHA-256 |
| The daily seal | **No engine code exists.** The mock shows it, and nothing in `src/` makes one | Not planned | Not planned | Out of this plan until Steve says what the daily seal shows. It would be new engine code, which section 7 rules out |
| Feistel | `Des.cs` | `DesWalk` (initial permutation, 16 rounds of left and right halves, expansion, S-boxes, permutation, subkeys) | `/api/walk/des` | FIPS 46-3 or SP 800-17 known answers |
| Diffie-Hellman | `DhGroup14`, `BigUInt.ModPow` | `DhWalk` (square and multiply rows; a small prime for reading, group 14 for the real run) | `/api/walk/dh` | Python `pow()`, as `dh-group14-rfc3526.nsv` does today |
| X25519 | `X25519`, `Montgomery` | `X25519Walk` (the ladder: one row per bit, the swap, the 4 field values) | `/api/walk/x25519` | RFC 7748 section 5.2 vectors |
| A signature (Q2) | `Ed25519` (if Q2 is A) | `Ed25519Walk` (r, R, k, S, then verify) | `/api/walk/ed25519` | RFC 8032 section 7.1 vectors |
| TLS 1.3 key schedule | `Tls13KeySchedule` | `Tls13ScheduleWalk` (each Extract and Derive-Secret, with its label and transcript hash) | `/api/walk/tls13/schedule` | RFC 8448 section 3 trace, as `tls13-rfc8448.nsv` does today |
| TLS 1.3 messages and the chain | Trace events `tls.handshake.sent` and `.received`, lesson 4's certificate parse | None. The trace already holds them | Existing session routes | Lesson 5's and lesson 4's clauses |

The Attacks index needs no engine data: `run-attack` already plays each run, and each run's check is already a trace event.

## 5. Slices and the work they change

| Slice | Builds | Closing check | Changes existing work |
|---|---|---|---|
| P0 | This plan, Jared's read, Steve's answers to section 8 | Steve's answers recorded in this file | None |
| P1 section shell | The 3-section switch and the grouped rail, from Nancy's lines. No engine change | The specs pass with every lesson reachable. 12 of 12 lessons placed | Builds on Nancy's shell (#196). The ux-refresh slices stay as planned |
| P2 = W1b | The AES walk in section 2, chapter 1, with the long text (R1) | W1b's clauses, plus a long-text clause | **W1b becomes the AES walk in section 2.** It takes W2's long text forward. W2 keeps the S-box build, tap-a-byte and the flip spread |
| Stop: show Steve | Steve steps through section 2 in the app | His reaction in `docs/learnings.md` | Unchanged stop from `walkthrough-design.md` |
| P3 Attacks index | `attacks.json`, the list by kind, one attack screen | 52 of 52 runs reachable, each plays its run and shows its check | None to the tours |
| P4 Handshake walk | The TLS 1.3 message walk, the key schedule walk, the chain view | RFC 8448 values, lesson 4 and 5 clauses | Takes **W4** (lesson 5 record walk) and the lesson 4 half of **W3** |
| P5 W1c | Chapter 2 modes, unchanged | W1c's clauses | Unchanged, now inside section 2 |
| P6 HMAC and chain | `Sha256Walk`, `HmacWalk`, `SealChainWalk` | FIPS 180-4 and RFC 4231 | Takes lesson 2 from **W5** |
| P7 Diffie-Hellman | `DhWalk` | `pow()` references | Takes the lesson 3 half of **W3** |
| P8 Elliptic curves | `X25519Walk`, then the signature walk from Q2 | RFC 7748, RFC 8032 | New |
| P9 Feistel | `DesWalk` | DES known answers | New |

The kill condition in section 6 covers P0 to P3. P4 onward is a second plan step, which Steve orders after his look.

## 6. Kill condition

This plan's first step ends when all of these hold, by **2026-11-27**:

1. 3 of 3 sections are live in the app.
2. 12 of 12 lessons are placed, with Q1 answered.
3. 52 of 52 attack runs are reachable from the Attacks section, and each plays its run.
4. The AES walk (W1b) runs in section 2, and the long text is on screen on every technique tab that exists.
5. Steve has stepped through each section in the app and reacted.

A progress report states these 5 counts. It does not substitute the fact that building continued.

## 7. Non-goals

1. No new lesson and no tour rewrite. Sections group what exists.
2. No new crypto in the engine. Every walk reads code that already runs.
3. No change to W1a's frozen walk types.
4. No change to the acceptance clause ids.

## 8. Questions for Steve

| Id | Question | Option A | Option B | My pick |
|---|---|---|---|---|
| Q1 | Lessons 6 (DUKPT), 8 (SSH), 9 (the bridge) and 10 (client proof) are neither the TLS chain nor a method you named. Where do they go? | Handshake holds every protocol (8, 9, 10), and DUKPT (6) goes to Techniques as a key scheme | A fourth section, "Protocols in the field", for 6, 8, 9 and 10 | **A.** It keeps your 3 sections, and each of the 4 lessons is a handshake or a key method |
| Q2 | Elliptic curves: by "ECDSA too", do you mean a signature walk on the curve the course already runs, or ECDSA itself? | Ed25519 (EdDSA), which the course runs today in lessons 4, 5 and 10 | ECDSA on P-256, which needs new engine code | **A.** It walks code the lessons run. ECDSA can come later as its own slice |
| Q3 | Attack runs: one place, or two? | Each run stays in its tour step, and Attacks is a second door to the same runs | Each run moves out of its tour into Attacks only | **A.** The tours keep teaching in order, and no tour or clause changes |
| Q4 | Lesson numbers: keep them inside the sections? | Keep 0 to 11, so section 1 shows 0, 4, 5, 7, and so on | Renumber inside each section | **A.** Tests, clauses, tour ids and the docs all name lessons by number |

Nancy may add 1 screen question here, which makes 5.

## 9. Prior art

Checked: `docs/walkthrough-design.md` (the AES pilot, section 6 slices, section 9 open list), `docs/ux-refresh-plan.md` (the shell and the walk root), and the 12 tour files for the attack runs. The structure follows a course table of contents grouped by subject, which the app already half has in its lesson rail. I did not consult the system-design catalog: this is a screen grouping over existing data, with no load, storage or service question.

## Disposition

Plan only. Jared reads it first. Steve answers section 8. Then the lead starts P1.
