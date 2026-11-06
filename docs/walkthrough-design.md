# MMP.NetworkSecurity: walkthrough design

Author: Richard. Date: 2026-11-06. Status: design only, for Jared's review and Echo's clauses. No product code. Branch `docs/walkthrough-design`, from main `7b569a1`.

## The two changes I would make

1. **Add one Host query, `GET /api/sessions/{id}/walk/aes`.** It runs a new walk method beside the real AES path, on the key and the text of the real lesson 1 run. It adds no trace event, so all 22 golden traces stay as they are.
2. **Teach the block and the mode as two chapters.** Chapter 1 walks the text block through AES and back in ECB, because only ECB shows readable letters going in and coming out. Chapter 2 walks a counter block through AES and XORs the text, because that is what lesson 1's GCM message did. Its result must equal the bytes on the wire.

## Conclusion

1. The AES walk has a working spike. It matched all 372 FIPS 197 round values and all 4 GCM blocks of a real lesson 1 run (section 3.6).
2. `EncryptBlock` and `DecryptBlock` do not change. The split of SubBytes and ShiftRows lives only in the walk path.
3. Show keys OFF closes the walk. Every state in the walk gives away the key, so a fingerprint cannot stand in for it (section 3.5).
4. Lessons 3, 4, and 5 show key pairs in action. Lesson 7 shows the one true public-key box (section 5).
5. No slice adds an event to an engine stream. Echo re-records nothing (section 4).

## 1. What each lesson should walk

"Today" means what the trace and the public engine calls give on main `7b569a1`. Event names and counts come from `acceptance/golden/net10/lab-NN.ndjson`.

| Lesson | Process the learner should watch | Can the engine show it today? | What it needs | Slice |
|---|---|---|---|---|
| 1 AES | KeyExpansion, each round, the inverse, and each mode around the block | **No.** The trace gives the text, the wire bytes, and the key. The rounds run inside `AesKey` | `AesKey.WalkEncrypt`, `WalkDecrypt`, `WalkKeyExpansion` | W1, W2 |
| 2 Seals | HMAC: key xor ipad, inner hash, key xor opad, outer hash. Then the length-extension forgery | **Part.** `seal.message.*` and the avalanche `measure.result` show results. The two HMAC passes stay inside `Hmac.Compute` | A query built on public `IHash`, pinned to `Hmac.Compute`. SHA-256 rounds stay hidden | W5 |
| 3 Key agreement | Each side makes a pair, shares cross, each side mixes, both reach one secret. ML-KEM's open box | **Yes, by value.** `kex.share.computed` 6, `kex.secret.computed` 6, messages 10. The 255-step ladder stays hidden, and it would teach nothing | One try-it (section 5). No new engine call for the walk | W3 |
| 4 Who are you | Sign, check, and each of the chain checks | **Part.** `check.result` 8 names each check. The sides of `S*B = R + h*A` stay inside `Ed25519.Verify` | The key-pair bench (section 5). `Ed25519.WalkVerify` only if Jared wants the equation on screen | W3 |
| 5 TLS 1.3 | The three jobs in order, the key ladder, and one sealed record | **Mostly.** `tls.handshake.*` 14, `secret.derived` 22. One record's AES-GCM is hidden | The W1 GCM walk on a record, with its nonce (IV xor sequence) and additional data. The speed bench (section 5) | W4 |
| 6 Key per sale | The KSN bit walk from the initial key to a sale's key. The PIN block, format 4 | **Part.** `dukpt.key.derived` 11 and `dukpt.key.erased` 5 show one key per sale. `WalkDown` hides the keys on the path. `PinBlock.EncryptFormat4` hides its steps | A query over public `DukptDerivation` calls, and a split of `PinBlock` into walk steps | W5 |
| 7 The old world | The RSA box, the PRF, and one MAC-then-encrypt CBC record | **Part.** `secret.derived` 34 and `tls11.message.*` show values. `Pkcs1.EncryptV15` hides the padding, and the record build is one call | A record walk that reuses the W2 CBC chapter | W5 |
| 8 SSH | Key exchange, the exchange hash, and one packet's cipher and seal | **Mostly.** `ssh.message.*` 112, `secret.derived` 40, `ssh.weak.*` 6. The inputs to the hash are hidden | A query over the same bytes for one packet | W5 |
| 9 Bridge | One PIN crossing two hops inside two channels | **Yes.** `ce.envelope.taken`, `gateway.envelope.relayed`, and `pin.block.locked` feed `OnionPanel` | Tour text only | W6 |
| 10 Client proof | Certificate, challenge, signed token, DPoP proof, role check | **Yes.** `auth.message.*` 20, `check.result` 34, `TokenPanel`. The signature itself is lesson 4's | Tour text only | W6 |
| 11 Timing | Each guess, its measured time, and the byte it reveals | **Yes.** `TimingPanel` reads the lab's report. This lesson has no golden trace | Tour text only | W6 |

## 2. The AES pilot

### 2.1 What the learner does

The learner runs lesson 1 and opens the **AES walk** tab. The tab holds two chapters.

| Chapter | Steps on screen | Truth it carries |
|---|---|---|
| **1. Inside the block** (mode ECB) | Pick text block 1 to 4. KeyExpansion. First AddRoundKey. Rounds of SubBytes, ShiftRows, MixColumns, AddRoundKey. Final round with no MixColumns. Then InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns, in FIPS 197 section 5.3 order, back to `Pump four is ok.` | This is AES with nothing around it. The screen states if this block went on the wire in this run |
| **2. How lesson 1 sent it** (mode GCM) | Pick the block. The nonce plus a counter makes the counter block. AES locks the counter block, with the same round steps. The result is the key stream. Text XOR key stream gives the cipher block. The wire block sits beside it. The receiver runs the **same forward AES** on the same counter and XORs again | AES never touches the text in GCM. The receiver never runs the inverse cipher. The wire match is a live check |

Each state shows as a 4x4 grid. A cell shows its hex byte, and its letter when the byte is printable. Bytes fill **columns first**, by FIPS 197 section 3.4: `s[r, c] = in[r + 4c]`. So `Pump` is the first column. A row-first grid would make ShiftRows look wrong, so a clause pins this.

Key size: chapter 1 offers 128, 192, and 256 bits, which give 10, 12, and 14 rounds. Chapter 2 stays on the run's AES-128 key.

### 2.2 Decision: ECB is the inverse cipher's home

| Option | Readable letters in and out | Sent in the control run | Result |
|---|---|---|---|
| **ECB (chosen)** | Yes | Text: no, only under attack `L1-use-ecb`. Picture: yes | Best for seeing AES itself. The screen states the gap |
| CBC | No. AES takes `IV xor text`, so the grid starts as junk | Yes, `TextCbc` | Truest to the run, and worse as the first view. It comes in W2 |
| GCM only | No. AES takes a counter | Yes | Has no inverse cipher, so it cannot carry the decrypt walk |

Why ECB: Steve asked to see the letters come back. In ECB, the grid holds the letters at both ends. The wire status keeps this truthful:

- On a control run, the panel says: "This run sent the text in CBC and GCM. It did not send this block in ECB. Run the ECB attack to send it, and the walk will match the wire."
- On the `L1-use-ecb` fork, the status is `match`. The spike confirmed this.

**What would change my mind:** Jared or Steve reads the `not-sent` line and still finds a walk of an unsent block misleading. Then CBC becomes chapter 1's default, at the cost of one XOR step and readable letters at the start.

### 2.3 What chapter 2 leaves out

The pilot walks one data counter. GCM also runs AES on an all-zero block (the hash key) and on the nonce with counter 1 (the tag mask). Data blocks start at counter 2. `Gcm.cs:88-101` and the spike agree on this: block 1's counter ends in `00000002`.

The pilot does not walk GHASH. The panel states that the tag exists, that the receiver checks it first (`Gcm.cs:40-45`), and it shows the `GCM tag` result from the run's own `check.result` event. A flip fork gives wire status `differs`, and the same panel shows the failed tag.

### 2.4 Resolution semantics

| Question | Answer |
|---|---|
| Which key runs? | At 128 bits, the key the run used, read from the run's `aes.key` secret. At 192 or 256 bits, a practice key from `new SeededRandom(session.Seed ^ keyBits)` |
| When is it chosen? | At each query. The run's key is fixed when the run starts |
| Where is the choice visible? | `keySource` in the reply. The panel shows "This run's key" or "A practice key. It never ran in the lesson" |
| A learner's own key? | The walk reads the key the run used, so `Mine` needs no separate path |
| No session, or a loaded replay? | `SESSION_NOT_FOUND`. A replay has no `LabSession`, so the pilot has no walk for it |
| Several identities? | One learner, one machine. This is the same non-goal as `modes-design.md` section 2.1 |

### 2.5 Controls, after a deletion pass

| Decision | Control |
|---|---|
| Which chapter | Two tabs |
| Which block | One picker, 1 to 4 |
| Which key size | One selector, chapter 1 only |
| Move through steps | Back, Next, and round chips to jump |

Cut: a play button, a speed slider, a separate encrypt/decrypt switch (decrypt follows encrypt in the one step list), and an S-box page.

## 3. Real data rule

### 3.1 The rule

Every state on screen comes from the C# engine in this query. The app holds no S-box, no round math, and no sample states. The app only compares two hex strings and formats them. A clause scans `app/src` for the S-box bytes to enforce this.

### 3.2 How SubstituteAndMove splits

`EncryptBlock` and `DecryptBlock` keep `SubstituteAndMove`, unchanged. The walk path uses two small loops:

- `Sub(state, box)`: `state[i] = box[state[i]]`.
- `Move(state, map)`: `state[i]` takes the old `state[map[i]]`.

Both use the same `Sbox`, `InverseSbox`, `ShiftRowsMap`, and `InverseShiftRowsMap`. The walk calls the real `AddRoundKey`, `MixColumns`, and `InverseMixColumns`. So only those two loops and the order of the calls are new.

**The trade.** The round order now lives in two places, and a change to one needs a change to the other. That is a real DRY cost. I accept it, because a single path needs a branch per step in the path that lab traces and A2 use, and it still could not show the split without a second branch. Two guards pin the copies:

1. **At run time.** Each walk also calls the real method on the same input and throws `AES_WALK_DIVERGED` on any difference. Key expansion checks each word against `_roundKeys`.
2. **In acceptance.** Echo's FIPS clauses compare every state, and a random clause compares each walk with the BCL.

**What would change my mind:** a benchmark that shows an observer branch costs nothing measurable on both builds, and a reason to walk more paths than these two.

### 3.3 Core types: C# 3, both builds

New file `src/NetSec.Core/Crypto/AesKey.Walk.cs`. `AesKey` gains the word `partial`. The CF project's `..\NetSec.Core\**\*.cs` picks up the file with no project edit.

```csharp
namespace NetSec.Crypto {
  public enum AesStepKind { AddRoundKey, SubBytes, ShiftRows, MixColumns, InvShiftRows, InvSubBytes, InvMixColumns }

  public sealed class AesStep {               // Immutable. Byte arrays are copied at construction
    public readonly AesStepKind Kind;
    public readonly int Round;                // Encrypt: 0 to Nr. Decrypt: Nr down to 0
    public readonly byte[] State;             // 16 bytes after this step, in = r + 4c order
    public readonly byte[] RoundKey;          // AddRoundKey only. Else null
  }
  public sealed class AesBlockWalk { public readonly int Rounds; public readonly byte[] Input, Output; public readonly AesStep[] Steps; }
  public sealed class AesKeyWord {            // One row of the FIPS 197 appendix A tables. An unused cell is null
    public readonly int Index;
    public readonly byte[] Previous, Rotated, Substituted, Rcon, AfterRcon, KeyBack, Word;
  }
  public sealed partial class AesKey {
    public AesBlockWalk WalkEncrypt(byte[] block);   // Throws AES_WALK_DIVERGED if it differs from EncryptBlock
    public AesBlockWalk WalkDecrypt(byte[] block);   // Throws AES_WALK_DIVERGED if it differs from DecryptBlock
    public AesKeyWord[] WalkKeyExpansion();          // Nb * (Nr + 1) rows
  }
  public static class Gcm {                   // Added to Gcm.cs
    public static byte[] CounterBlock(byte[] nonce, int blockIndex);   // nonce, then 32-bit blockIndex + 2
  }
}
namespace NetSec.Labs {
  public enum AesWireStatus { Match, Differs, NotSent }
  public sealed class AesEcbWalk { public int KeyBits; public byte[] Plain; public AesKeyWord[] KeyWords; public AesBlockWalk Encrypt, Decrypt; public byte[] WireBlock; public AesWireStatus Wire; }
  public sealed class AesGcmWalk { public int Block; public byte[] Nonce, CounterBlock, Plain, KeyStream, Cipher, WireBlock; public AesKeyWord[] KeyWords; public AesBlockWalk Lock; public AesWireStatus Wire; }
  public static class AesWalks {              // Pure. Same input, same output. No session, no socket
    public static AesEcbWalk Ecb(byte[] key, byte[] plainBlock, byte[] wireBlockOrNull);
    public static AesGcmWalk Gcm(byte[] key, byte[] nonce, int block, byte[] plainBlock, byte[] wireBlock);
  }
}
```

`Gcm.CounterBlock` is new and pure. `CounterCrypt` stays as it is. The wire match catches a drift between the two. `ErrorCodes` gains `AesWalkDiverged`, `WalkNotBuilt`, `WalkWaitingForWire`, `WalkKeySizeNotInRun`, and `WalkBadArgument`.

Language limits, checked by the spike: no optional parameters, no records, no expression bodies, no target-typed `new`. Types use only `byte[]`, `Buffer`, and `List<T>`.

### 3.4 Host route and call path

`src/NetSec.Host/AesWalkRoute.cs`, C# 14, net10. It joins `Program.cs` beside `SecurityRoutes.Map`.

```
GET /api/sessions/{id}/walk/aes?mode=ecb|gcm&block=0..3&keyBits=128|192|256
```

Call path:

1. `AesWalkRoute` reads `security.ShowKeys`. OFF returns 409 `KEYS_HIDDEN`, as the key log route does.
2. `sessions.Find(id)`. Null returns 404 `SESSION_NOT_FOUND`.
3. `session.Lesson != 1` returns 409 `WALK_NOT_BUILT`.
4. `AesWalkFacts.Read(session.After(0))` filters on `StoredEvent.Type` and `Message`, and parses only those shown lines. It takes `aes.key`, the `plain` of `TextGcm1`, and the `wire` of the client's `wire.sent` for `TextGcm1` and `TextEcb`. `LabSession` holds no new state.
5. `AesWalks.Ecb` or `AesWalks.Gcm` runs. For chapter 1 at 192 or 256 bits, the Host draws the practice key first.
6. `AesWalkJson.Write` writes the reply. English stays out of Core.

Why the route takes a session id and no bytes: a client cannot send a canned key or block, so the real data rule holds at the Host. The toggle also holds at the Host boundary, as in `modes-design.md` section 6.4.

Reply, trimmed. Every error carries `code`, `message`, `retryable`, and `requestId`.

```json
{
  "mode": "gcm", "block": 0, "blockCount": 4, "keyBits": 128, "rounds": 10, "keySource": "run",
  "plainHex": "50756d7020666f7572206973206f6b2e",
  "keyWords": [ { "i": 4, "previous": "...", "rotated": "...", "substituted": "...", "rcon": "...", "afterRcon": "...", "keyBack": "...", "word": "..." } ],
  "encrypt": { "input": "...", "output": "...", "steps": [ { "kind": "AddRoundKey", "round": 0, "state": "...", "roundKey": "..." } ] },
  "decrypt": null,
  "gcm": { "nonce": "...", "counterBlock": "...", "keyStream": "...", "cipher": "..." },
  "wire": { "status": "match", "message": "TextGcm1", "offset": 16, "hex": "..." }
}
```

In ECB, `decrypt` holds the inverse walk and `gcm` is null. In GCM, `encrypt` walks the counter block and `decrypt` is null, so the reply itself says that no inverse cipher ran.

| Case | Status and code |
|---|---|
| Show keys OFF | 409 `KEYS_HIDDEN` |
| Lesson other than 1, in the pilot | 409 `WALK_NOT_BUILT` |
| `mode=gcm` with `keyBits` other than the run's | 400 `WALK_KEY_SIZE_NOT_IN_RUN` |
| A step-mode run has not sent `TextGcm1` yet | 409 `WALK_WAITING_FOR_WIRE`, `retryable: true` |
| A bad mode, block, or key size | 400 `WALK_BAD_ARGUMENT` |
| A guard fired | 500 `AES_WALK_DIVERGED` |

### 3.5 Show keys OFF

**Decision: OFF closes the walk.** Round 0's AddRoundKey gives `state = text xor key`, and the text is public in this lesson, so one state gives the whole key. Any later round key also gives the key, because the key schedule runs backward. A fingerprint per cell would teach nothing.

The walk loses its teaching with the toggle OFF. `modes-design.md` section 6.5 says each lesson keeps its comparison. That stays true for the lesson, because the panels of section 6.5 still run. The walk tab shows: "Show keys is off. Every step here gives away the key, so this walk stays closed. Turn Show keys on to walk."

**The flip race.** This is the same class as PRs #140, #141, and #143. A reply can be in flight when the toggle flips, and it does not pass through `ShowKeysFence`. The fix sits in the app:

1. `walk.ts` holds a generation counter. The `security.show-keys` frame raises it, and the store clears the walk.
2. A reply whose generation is old is dropped.
3. The walk reply never enters a session file, `/events`, or a save.

Echo gets a clause for each of the three.

### 3.6 Spike output

Throwaway project in the session scratch folder. The walk file is compiled at `LangVersion 3`, beside a copy of `AesKey.cs` with `partial` added. It references the built `NetSec.Core.dll` to run the real lab with seed 20261105.

```
runtime 10.0.14, walk file compiled at LangVersion 3
C.1 AES-128: rounds 10, encrypt 52 of 52 listed values match in order, inverse 52 of 52
C.2 AES-192: rounds 12, encrypt 62 of 62 listed values match in order, inverse 62 of 62
C.3 AES-256: rounds 14, encrypt 72 of 72 listed values match in order, inverse 72 of 72
Appendix A.1 row 4: 09cf4f3c cf4f3c09 8a84eb01 01000000 8b84eb01 2b7e1516 a0fafe17
Appendix B output: 3925841d02dc09fbdc118597196a0b32 in 40 steps
lesson 1 control run: key 25d902f8bb264587039f1a2d72b0bcb8, text Pump four is ok., TextGcm1 wire 96 B, TextCbc wire 100 B
GCM block 1: counter e4f00aae0569f1494f973a4600000002, key stream c841554b4c810b0070e4be779ad72907
GCM: AES on the counter, xor the text, equals the wire cipher on 4 of 4 blocks
CBC block 1: AES of (IV xor text) equals the wire block: True
ECB text block: Pump four is ok. -> e968a3f7931ba4124a59f83fce569eec -> Pump four is ok.
real AesKey.EncryptBlock on the same block: e968a3f7931ba4124a59f83fce569eec
L1-use-ecb run: TextEcb wire block 1 equals the walk output: True (same seed, so same key)
1,000,000 EncryptBlock: 431 ms. 10,000 WalkEncrypt: 63 ms
AES-128: rounds 10, 40 encrypt steps, 44 key words, about 5 KiB of hex for encrypt plus decrypt plus key words
AES-192: rounds 12, 48 encrypt steps, 52 key words, about 6 KiB of hex for encrypt plus decrypt plus key words
AES-256: rounds 14, 56 encrypt steps, 60 key words, about 7 KiB of hex for encrypt plus decrypt plus key words
```

The 186 encrypt values and 186 inverse values come from FIPS 197 (2001 edition), appendix C. The comparison is strict, by position. The walk file and the `AesKey` copy also compiled against the CF 3.5 references in `E:\dev\tools\netcf35-ref`, with 0 errors and 0 warnings.

Limits of the spike:

1. The walk file ran on the desktop CLR, on the copy of `AesKey`. It compiled for CF and did not run on it.
2. No route, no app panel, and no Show keys path ran.
3. Same-seed runs give the same key, so the ECB match compares two runs.

**Which FIPS edition.** FIPS 197-upd1 (2023) is the source of record for the algorithm: section 3.4 for the state, 5.1 for the cipher, 5.2 for key expansion, 5.3 for the inverse. Its appendix B gives the AES-128 cipher example, and its appendix A gives the key tables. Upd1 removed the appendix C round values and points to NIST's example site. Its appendix D says the technical specifications did not change. So the inverse round values come from the 2001 edition, the same source `acceptance/vectors/SOURCES.md` already names. Jared should confirm this choice.

### 3.7 App shape

| File | Holds |
|---|---|
| `app/src/walk.ts` | `fetchAesWalk`, the generation counter, and pure functions: `gridOf(hex)`, `changedCells(before, after)`, `describeStep(prev, step)`. No Vue, so a test can call each one |
| `app/src/walk-gloss.json` | The words for each step kind and chapter. A15 and A15a scan this file, so `docs_checks.py` gains it |
| `app/src/components/AesWalkPanel.vue` | Tabs, picker, grid, Back, Next, round chips. Test ids `aes-walk-*` |
| `app/src/App.vue` | One more entry in the panel tab list, shown when the run holds `aes.key` |
| `app/src/tours/lesson-01.json` | Two new steps. One follows "ECB locks each block alone", and one follows "CBC and GCM hide the shape". They land after #145 |
| `app/src/tour.ts` | A new `tryIt.expect` type, `walk-finished`, for those two steps |

`describeStep` states what changed, from the real bytes:

| Step | What it says |
|---|---|
| SubBytes | Each byte is swapped by the S-box table. It names the selected cell: `53` went to `ed`, from row 5, column 3 |
| ShiftRows | Row 0 stays. Rows 1, 2, 3 move left by 1, 2, 3 |
| MixColumns | Each column is replaced by a mix of its four bytes. It shows the column before and after, and the FIPS formula with no math run in the app |
| AddRoundKey | Each byte is XORed with the round key. It shows the state, the round key, and the result |
| KeyExpansion | Each word comes from the word before it and the word one key back. Every Nk words it also rotates, swaps by S-box, and takes a round constant. AES-256 has one more S-box swap at `i mod 8 = 4` |

Nancy owns the panel and its layout, and `feat/ux1-bytes` already changes the same area. So this panel starts after her branch merges.

## 4. Effect on golden traces

**Echo re-records nothing.**

| Item | Effect |
|---|---|
| `acceptance/golden/{net10,cf}/lab-NN.ndjson`, 22 files | No change. The walk writes no `TraceEvent`, and `Lesson01Aes` does not change |
| `A17.mock.golden-trace-equal` | Stays green. It runs in every W slice as the proof |
| `A1.aes-*`, `A2` | No change. The real AES path has no edit |
| `session.save`, session files | No change. The walk reply is never stored |
| `acceptance/contract/` | Gains the types in section 3.3 and the route in section 3.4 |
| Tour step counts | Lesson 1 gains two steps. `e2e/lesson-1.spec.ts` reads ids from the tour file, and its try-it actions gain the walk |

**The rule for later slices.** A walk is a query over the run's stored bytes. If a value exists only inside a run and no event holds it, the Host writes it on its own stream, as `<sessionId>/keys` does (`SessionManager.cs:238`). `GoldenClauses.Run` runs with no Host, so that stream never reaches a golden. Any slice that breaks this rule must name its goldens and ask Echo first.

## 5. Feel the difference: symmetric and asymmetric

Source of facts: `E:\dev\ns-lesson1-facts.md`. **Key pairs act in lessons 3, 4, and 5. Lesson 7 adds the box. Lesson 1 is the one-key contrast.**

| Lesson | The learner does | The learner feels | Engine call |
|---|---|---|---|
| 1 | Walks encrypt, then decrypt, and sees the same round keys in reverse order. Then flips one key bit and decrypts | One key does both jobs. A wrong key gives junk, and AES gives no error | `WalkDecrypt` under the flipped key, W2. Query gains `flipKeyBit` |
| 3 | Sees each side mix its own private part with the other's public share, and both reach one secret. Then plays the eavesdropper: "mix" the two public shares, and sees a value that does not match | Two strangers reach one secret, and that secret never crossed the wire | `X25519.Mult` on real bytes. Jared must approve the wording, because one failed try does not prove the hard problem |
| 4 | Key-pair bench. Sign with the private key, and check with the public key. Change one byte, and the check fails. Sign with `attacker-ed25519`, and the check fails. The bench offers no "sign with the public key" button, and the text says why | One owner can sign, and anyone can check. A tag from lesson 1 could come from either side | `Ed25519.Sign`, `Ed25519.Verify`. New route `POST /api/walk/signature` |
| 5 | Sees which job each part did: hybrid exchange (asymmetric), certificate signature (asymmetric), AES-GCM records (symmetric). Then presses **Measure**: AES on 1 MB, and repeated Ed25519 signs and X25519 mixes | Asymmetric sets up the key and symmetric carries the data. The speed gap is a number from this machine, labelled as such | `Modes.Ctr`, `Ed25519.Sign`, `X25519.Mult`. New route `POST /api/walk/speed` |
| 7 | L7-S05 points back to the bench: this is the one place a public key locks a secret | Lock and sign are two different verbs | Tour text, W5 |

The words follow the fact sheet's table of wrong statements: "sign" and "lock" stay separate verbs, and a public key never "decrypts".

## 6. Slices and build order

**Program design layer:** section 3.3 fixes types and signatures, section 3.4 fixes the route and call path, section 3.7 fixes the app files. A builder picks local names only.

| Slice | Builds | Closing check | Owner |
|---|---|---|---|
| W0 | This doc. Jared's review. Echo's clauses, from sections 2 to 4, red | Clauses exist and fail with a named code | Richard, Jared, Echo |
| **W1a** skeleton | `AesKey.Walk.cs`, `Gcm.CounterBlock`, `AesWalks`, the route, ECB and GCM replies. No UI | FIPS, wire, BCL, toggle, and golden clauses pass on both builds. `tools/gate.ps1` green | Richard |
| **W1b** small section | `walk.ts`, `AesWalkPanel.vue`, chapter 1 at 128 bits, encrypt and decrypt | e2e: a learner reaches `Pump four is ok.` by Next alone. Grid order clause. S-box scan | Nancy |
| **W1c** | Chapter 2, block picker, key sizes, the flip guard, two tour steps, gloss | e2e on GCM match and on the flip. A15, A15a by a reader who did not write it | Nancy, Richard |
| W2 | CBC chapter with a real wire match, the true home of the control run's inverse cipher. `flipKeyBit` | Wire match on all 5 CBC blocks, padding block named | Richard, Nancy |
| W3 | Lesson 3 try-it, lesson 4 bench | Clauses on each check result | Richard, Nancy, Jared on wording |
| W4 | Lesson 5 record walk and speed bench | Record walk equals the wire. The number's label names the machine | Richard, Nancy |
| W5 | Lessons 2, 6, 7, 8 queries, one PR each | A reference check per lesson, from Jared | Richard, Jared |
| W6 | Lessons 9, 10, 11 tour text | A15, A15a | Richard |

W2 onward starts only after W1 passes the kill condition. Corrections from any slice go in `docs/learnings.md`, and later slices read it.

**Kill condition for the pilot.** Both parts by **2026-11-13** (date proposed, the lead may move it):

1. Steve steps through one block, encrypt and decrypt, in the app, and says he follows it.
2. Echo's clauses for W1 pass, N of N, from a run outside the builder's worktree.

If Steve does not follow it after 2 rounds of word changes, stop and re-plan the view. Do not start W2.

**Clause list I expect from Echo** (Echo writes them, and owns the wording):

| Theme | What a clause checks |
|---|---|
| Round values | Every encrypt and inverse state for FIPS C.1, C.2, C.3, by position |
| Key words | FIPS appendix A rows, for all three sizes |
| Step counts | 40, 48, 56 per direction. The last encrypt round has no MixColumns. The decrypt order is section 5.3's |
| Real run | Key and block from a live session's trace, with the BCL as referee on the walk's output |
| Wire | `match` on all 4 GCM blocks. `not-sent` on a control ECB. `match` on the `L1-use-ecb` fork. `differs` on the `L1-flip-gcm` fork |
| Real path | `WalkEncrypt` equals `EncryptBlock` on 10,000 random inputs |
| Toggle | OFF gives 409 `KEYS_HIDDEN`. A flip drops an in-flight reply. No state reaches a session file |
| No app math | No S-box bytes under `app/src` |
| Grid order | Row r, column c shows byte `r + 4c` |
| Golden | `A17.mock.golden-trace-equal` still passes |

**Boundary for the builders.**

| Line | Value |
|---|---|
| May do without asking | Local names, private helpers, test ids under `aes-walk-` |
| Needs Steve | A change to the kill condition. Any walk that shows a key with Show keys OFF |
| A gate refuses | Stop and report, with the command and the refusal quoted |
| The walk differs from FIPS or the BCL | Stop. It is a defect, so never edit the vector |
| Sources disagree | Jared decides on the crypto, and the lead on scope |

## 7. Prior art

**System-design catalog.** I read `E:\dev\MMP.Library\docs\system-design-catalog.md` and the Playbook's CQRS section.

| Item | Note |
|---|---|
| Closest shape | **A read model beside a write model**, CQRS without event sourcing machinery. The lab writes the trace. The walk is a query computed from it, and it never writes back |
| Took | The split: the write side stays untouched, so its goldens hold. "CQRS does not require event sourcing" |
| Rejected | Asynchronous projection and a stored view. No staleness exists here, because the walk computes at the query |
| Where we differ | One learner on one machine. No scale pressure. The read side recomputes with the real engine, and that is the teaching |

**The arithmetic.** One learner, at most about 1 walk query per second while picking blocks. A reply is about 5 to 7 KiB. A walk costs about 6.3 microseconds in this test environment, against about 0.43 microseconds for `EncryptBlock`. Storage over three years is zero, since nothing is stored. So the design uses no cache, no streaming, and no per-step request. One reply holds the whole walk, and Next is a local move.

**Gem catalog.** I read `E:\dev\MMP.ProgrammingGems\INDEX.md`.

| Gem | Use |
|---|---|
| `decide-at-authoritative-boundary` | Applies. The Host decides the toggle and the facts, once, at the route. Mark `AesWalkRoute` |
| `server-replaces-never-merges` | Applies. The app replaces the whole walk on each reply and clears it on a flip. Mark `walk.ts` |
| A new gem? | No gem covers "an instrumented twin of a hot path, checked against the real path on every call". One use site so far. I record it as a candidate at W5, with Jared as SME, if the second walk type uses it too |

**CUPID, under pressure.** Predictable is the property most at risk, because a twin path can drift. The run-time guard answers that. Composable holds: `AesWalks` is pure, and lessons 5 and 7 reuse it. Domain-based holds: the types use the FIPS step names. Complexity hotspots: `describeStep` wants a lookup by step kind, and `AesWalkPanel.vue` stays thin because `walk.ts` holds the logic. SOLID adds nothing here.

## 8. Non-goals

1. No walk of GHASH, SHA-256 rounds, or the X25519 ladder in the pilot.
2. No walk of the padding block in W1. W2 names it.
3. No walk on a loaded replay or an OS transport session.
4. No change to `EncryptBlock`, `DecryptBlock`, or `CounterCrypt`.
5. No claim that this AES is production AES. `AesKey.cs:8` already says that table lookups can leak through a CPU cache, and the panel says so too.

## Disposition

Ready for Jared's review on the crypto wording and sections 2.2, 3.5, and 3.6, and for Echo's clauses. Do not start W1a until both are done.
