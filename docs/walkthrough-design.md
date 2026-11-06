# MMP.NetworkSecurity: walkthrough design

Author: Richard. Date: 2026-11-06. Revision 3, with Steve's depth links, the S-box view, the modes walk, the first grid view, and the lesson 6 steps. Status: design only, for Jared's review and Echo's clauses. No product code. Branch `docs/walkthrough-design`, from main `7b569a1`.

Sources of facts: FIPS 197, the engine, and Jared's sheet `E:\dev\ns-lesson1-facts.md`. Steve's web pages set depth and teaching order only (section 2.1).

## The two changes I would make

1. **Add three Host queries that run a new walk path beside the real AES path.** They read the key and the bytes of the real lesson 1 run. They add no trace event, so all 22 golden traces stay as they are.
2. **Teach AES in two chapters, in this order.** Chapter 1 opens one block: each step in order, for encryption and decryption, with the S-box lookup shown byte by byte. Chapter 2 shows how ECB, CBC, and GCM feed blocks through AES, with lesson 1's real messages. Chapter 2 is where the learner sees why ECB and CBC need the reverse steps and GCM does not.

## Conclusion

1. The walk has a working spike. It matched all 372 FIPS 197 round values. ECB, CBC, and GCM each matched the wire on every block of a real lesson 1 run (section 3.6).
2. `EncryptBlock` and `DecryptBlock` do not change. The split of SubBytes and ShiftRows lives only in the walk path.
3. The S-box tables come from the engine by a public route, so the S-box view stays open with Show keys OFF. The round states close with Show keys OFF, because one state gives away the key (section 3.5).
4. Lessons 3, 4, and 5 show key pairs in action. Lesson 7 shows the one RSA box (section 5).
5. No slice adds an event to an engine stream. Echo re-records nothing (section 4).

## 1. What each lesson should walk

"Today" means what the trace and the public engine calls give on main `7b569a1`. Event names and counts come from `acceptance/golden/net10/lab-NN.ndjson`.

| Lesson | Process the learner should watch | Can the engine show it today? | What it needs | Slice |
|---|---|---|---|---|
| 1 AES | KeyExpansion, each round, the S-box lookup, the inverse, and how each mode feeds blocks through AES | **No.** The trace gives the text, the wire bytes, and the key. The rounds and the tables stay private in `AesKey` | The walk path in sections 2 and 3 | W1 |
| 2 Seals | HMAC: key xor ipad, inner hash, key xor opad, outer hash. Then the length-extension forgery | **Part.** `seal.message.*` and the avalanche `measure.result` show results. The two HMAC passes stay inside `Hmac.Compute` | A query built on public `IHash`, pinned to `Hmac.Compute`. SHA-256 rounds stay hidden | W5 |
| 3 Key agreement | Each side makes a pair, shares cross, each side mixes, both reach one secret. ML-KEM's open box around a random value | **Yes, by value.** `kex.share.computed` 6, `kex.secret.computed` 6, `kex.message.sent` 10. The 255-step ladder stays hidden, and it would teach nothing | One try-it (section 5). No new engine call for the walk | W3 |
| 4 Who are you | Sign, check, and each of the chain checks | **Part.** `check.result` 8 names each check. The sides of `S*B = R + h*A` stay inside `Ed25519.Verify` | The key-pair bench (section 5). `Ed25519.WalkVerify` only if Jared wants the equation on screen | W3 |
| 5 TLS 1.3 | The three jobs in order, the key ladder, and one sealed record | **Mostly.** `tls.handshake.*` 14, `secret.derived` 22. One record's AES-GCM is hidden | The W1 feed on a record, with its nonce (IV xor record count) and its record header as extra data. The speed bench | W4 |
| 6 Key per sale | Base key, initial key, the counter, the future keys, and each sale's key used once and erased. Then the PIN block, format 4, which runs inverse AES at the bank. Section 1.1 gives the steps | **Part.** `dukpt.key.derived` 11 and `dukpt.key.erased` 5 show one key per sale, and `measure.result` gives the held count. The register contents and `WalkDown`'s keys stay hidden. `PinBlock.EncryptFormat4` hides its steps | A query that replays `DukptPinPad` and `DukptDerivation` from the run's `dukpt.initial` and `dukpt.bdk` secrets, and a split of `PinBlock` into walk steps | W5 |
| 7 The old world | The RSA box, the PRF, and one MAC-then-encrypt CBC record | **Part.** `secret.derived` 34 and `tls11.message.*` show values. `Pkcs1.EncryptV15` hides the padding, and the record build is one call | A record walk that reuses the W1 CBC feed | W5 |
| 8 SSH | Key exchange, the exchange hash, and one packet's cipher and seal. `aes128-ctr` runs forward AES on both sides | **Mostly.** `ssh.message.*` 112, `secret.derived` 40, `ssh.weak.*` 6. The inputs to the hash are hidden | A query over the same bytes for one packet | W5 |
| 9 Bridge | One PIN crossing two hops inside two channels | **Yes.** `ce.envelope.taken`, `gateway.envelope.relayed`, and `pin.block.locked` feed `OnionPanel` | Tour text only | W6 |
| 10 Client proof | Certificate, challenge, signed token, DPoP proof, role check | **Yes.** `auth.message.*` 20, `check.result` 34, `TokenPanel`. The signature itself is lesson 4's | Tour text only | W6 |
| 11 Timing | Each guess, its measured time, and the byte it reveals | **Yes.** `TimingPanel` reads the lab's report. This lesson has no golden trace | Tour text only | W6 |

### 1.1 Lesson 6 steps (later slice, AES stays the pilot)

Steve's Wikipedia page sets the order. It describes the older TDES form. **This engine runs AES DUKPT, so the page's counts do not apply.** Facts come from `DukptPinPad.cs`, `DukptDerivation.cs`, and `docs/lesson-6-names.md`. Jared's sheet has no DUKPT section yet, so I asked him to check this table.

| Fact | Wikipedia page (TDES form) | This engine |
|---|---|---|
| Future-key registers | 21 | 32 (`RegisterCount`, `DukptPinPad.cs:30`) |
| KSN | 80 bits | 12 bytes: 8-byte initial key id, then 4-byte counter |
| Counter | 21 bits | The 4-byte counter of the KSN |

| Step | The learner watches | Lane | Source |
|---|---|---|---|
| 1. Base key | One base key stays at the bank, and the reader never holds it | Bank | `dukpt.key.derived`, `dukpt.bdk` |
| 2. Initial key | The bank derives it from the base key and the key id. The reader holds the same bytes. Compare the two sides | Both | `dukpt.key.derived`, `dukpt.initial` |
| 3. Future keys | The reader fills its 32 registers from the initial key, then erases the initial key. A register table lights up | Reader | Replay, plus `dukpt.key.erased` |
| 4. Counter | The next counter, in binary. Its lowest 1 bit picks the register | Reader | Replay |
| 5. One sale | That register gives the derivation key, and the derivation key gives this sale's PIN key. The PIN block leaves with the KSN | Reader | `dukpt.key.derived`, `dukpt.pinKey.<c>` |
| 6. Erase | The reader may fill lower registers with child keys, then erases the used register. The held count runs 32, 31, 31, 30, 31, so it does not fall on every sale | Reader | `dukpt.key.erased`, `measure.result` |
| 7. The bank | The bank holds no per-reader key. It takes the KSN, walks from the base key through each 1 bit of the counter, and reaches the same PIN key | Bank | Replay of `DukptDerivation.WalkDown` |
| 8. A past key | Attack `L6-ask-past-key`: the reader cannot rebuild a used key. `L6-replay-sale`: the bank refuses a repeated KSN | Both | `check.result` |

**Words on screen.** "Erased" keeps the existing tour line: erasing clears a register in place, and a managed heap can keep copies.

**How the query stays real.** It builds a new `DukptPinPad` from the run's `dukpt.initial` bytes and key id, steps it to each sale, and reads `HeldKeys()`. Each replayed PIN key must equal the run's `dukpt.pinKey.<c>`, or the query throws `WALK_DIVERGED`. The replay writes no event, so the golden holds.

**Show keys OFF.** Unlike the AES states, this walk keeps its teaching with fingerprints: which register is full, and which keys match, needs no key byte. So OFF replaces key bytes with `TraceRedaction.Fingerprint`, as section 6.5 of `modes-design.md` does for this lesson.

## 2. The AES pilot

### 2.1 Depth and teaching order, from Steve's links

| Page | What it sets for us | Where it stops, and what we add |
|---|---|---|
| GeeksforGeeks, AES | Order: key sizes and rounds table, round keys, the 4x4 grid, the four steps, decryption. ShiftRows shows before and after | SubBytes and AddRoundKey show no values. Decryption gets 2 subsections. We show values at each step, and all 4 inverse steps |
| Wikipedia, AES | One picture per step, named in order: SubBytes, ShiftRows, MixColumns, AddRoundKey | Key schedule and inverse get little. We walk both |
| GeeksforGeeks, S-box | A table picture is expected | It traces no byte and gives no row and column rule. We trace a byte through the table, both ways |
| GeeksforGeeks, modes | A step-by-step feed per mode | ECB and CBC decryption are missing there. We show the unlock path for each mode |
| cybernews, AES | **The clearest guide to the shape Steve wants.** One short phrase and one key go through each step in order, with a 4x4 grid at each step. The fetch refused me with HTTP 403. Steve pasted the page, and the lead read it and sent me its order | Its grids are made up, and ours come from the engine. Its facts stay out, and Jared's sheet governs |

**Teaching order in the app.** This follows the cybernews order, with one phrase and one key from start to end: the block of `Pump four is ok.` and this run's key.

| # | Step | Where |
|---|---|---|
| 1 | Split the text into 16-byte blocks | Section 2.2, first view |
| 2 | Put one block in the 4x4 grid, by columns | Section 2.2, first view |
| 3 | KeyExpansion makes the round keys. The key size sets the rounds: 10, 12, or 14 in total | Section 2.2 |
| 4 | AddRoundKey with round key 0 | Section 2.2 |
| 5 | SubBytes, with one byte traced through the S-box | Sections 2.2, 2.3 |
| 6 | ShiftRows | Section 2.2 |
| 7 | MixColumns | Section 2.2 |
| 8 | AddRoundKey | Section 2.2 |
| 9 | Repeat for the other rounds | Round chips |
| 10 | The last round, with no MixColumns | Section 2.2 |
| 11 | Decryption, step by step, with the inverse table | Sections 2.2, 2.3 |
| 12 | Modes: ECB, CBC, GCM, with lock and unlock for each | Section 2.4 |

Round 1 shows each step in full. So step 5 opens the S-box view by itself on the first SubBytes, with the first cell selected. Later rounds keep it one click away.

Jared's sheet sections 5.7, 5.9, 5.11, and 5.13 list the lines on these pages that a lesson must not copy.

### 2.2 Chapter 1: inside the block

The learner runs lesson 1 and opens the **AES walk** tab.

**The first view teaches the grid.** A reader learns the fill order here, so this view must get it right.

1. The text shows split into 4 blocks of 16 bytes. The learner picks block 1 to 4.
2. The picked block drops into the grid one byte at a time, with Next. Each cell shows its position, 0 to 15.
3. The grid fills **down the first column, then down the next**, and the panel says so.

Block 1 fills like this. `·` marks a space byte.

| | Column 0 | Column 1 | Column 2 | Column 3 |
|---|---|---|---|---|
| Row 0 | `P` (0) | `·` (4) | `r` (8) | `·` (12) |
| Row 1 | `u` (1) | `f` (5) | `·` (9) | `o` (13) |
| Row 2 | `m` (2) | `o` (6) | `i` (10) | `k` (14) |
| Row 3 | `p` (3) | `u` (7) | `s` (11) | `.` (15) |

So the first column reads `Pump`, and the top row reads `P`, space, `r`, space. The round keys use the same grid. Then the steps run in the order of section 2.1:

| Part | On screen | Words that carry the truth |
|---|---|---|
| Label | The panel names the input | "A teaching example. AES runs on this text block alone, the way ECB uses it. This run did not send this block in ECB." The label changes to `match` on the `L1-use-ecb` fork |
| KeyExpansion | The round keys, built word by word | The key makes 11 round keys for AES-128 (13 for 192, 15 for 256) |
| Encrypt | AddRoundKey 0. Rounds 1 to 9: SubBytes, ShiftRows, MixColumns, AddRoundKey. Round 10: SubBytes, ShiftRows, AddRoundKey | The first SubBytes sees letters XOR round key 0. It never sees bare letters |
| Decrypt | AddRoundKey 10. Rounds 9 to 1: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns. Last: InvShiftRows, InvSubBytes, AddRoundKey 0. The grid reads `Pump four is ok.` | The same key, with the round keys from last to first. This is FIPS 197 section 5.3 order, and the only order that works with these round keys (sheet 5.1) |

Each state shows as a 4x4 grid. A cell shows its hex byte, and its letter when the byte is printable. The fill order comes from FIPS 197 section 3.4: `s[r, c] = in[r + 4c]`. A row-first grid would make ShiftRows look wrong, so a clause pins this on the first view and on every state.

Key size: a selector offers 128, 192, and 256 bits. The block stays 16 bytes. Only the rounds change.

What each step says:

| Step | What it says, from the real bytes | Picture |
|---|---|---|
| AddRoundKey | Each byte is XORed with the round key. This is the only step that uses the key. It is its own inverse | State, round key, result |
| SubBytes | Each byte is swapped with the S-box table. The table is public and fixed | Before and after, plus the S-box view (section 2.3) |
| ShiftRows | Row 0 stays. Rows 1, 2, 3 slide left by 1, 2, 3 | Before and after, rows marked |
| MixColumns | Each column is replaced by a mix of its 4 bytes, by a matrix with a special multiply. Ordinary multiply gives wrong bytes | The selected column before and after, and the matrix 2, 3, 1, 1. The app runs no math |
| InvShiftRows | Rows 1, 2, 3 slide right by 1, 2, 3 | Before and after |
| InvSubBytes | Each byte swaps back with the inverse table | S-box view, on the inverse table |
| InvMixColumns | Each column is unmixed, by the matrix 14, 11, 13, 9 | The selected column before and after |
| KeyExpansion | Each word comes from the word before it and the word one key back. Every Nk words, it also rotates, swaps by S-box, and takes a round constant. AES-256 adds one more S-box swap | One row of the FIPS 197 appendix A table |

### 2.3 The S-box view

**What the learner sees, on a SubBytes step:**

1. The learner clicks one cell in the grid. The cell shows, for example, `53`.
2. The byte splits into two hex digits: `5` and `3`.
3. A 16 by 16 table opens. The first digit lights row `5`. The second lights column `3`.
4. The cell where they cross lights up. It reads `ed`.
5. The grid's matching cell after the step shows `ed`, and the panel draws the link.

**On an InvSubBytes step**, the same view uses the inverse table. Row `e`, column `d` reads `53`. The panel says: "The inverse table undoes the swap. The S-box is not its own inverse, so decryption needs this second table."

| Fact on screen | Source |
|---|---|
| 8 bits in, 8 bits out, 256 entries. One table for every byte, round, and key. Public | FIPS 197 section 5.1.1, sheet 5.8 |
| The first digit picks the row and the second picks the column | FIPS 197 Table 4 |
| The S-box holds no secret. The key enters only through AddRoundKey | Sheet 5.8 |
| One changed byte stays one byte here. ShiftRows and MixColumns do the spreading | Sheet 5.8, 5.9 |
| KeyExpansion uses this same table | `AesKey.cs` `SubWord` |

**Real data.** The tables come from `AesKey`'s own `Sbox` and `InverseSbox`, through `GET /api/walk/aes/tables`. The app stores no copy in source. The spike checked that a table lookup equals the walk's swap on 320 of 320 cells, over SubBytes and InvSubBytes.

**Show keys OFF.** The tables are public, so the table and a free lookup stay open: the learner can type any byte. The grid and its real states stay closed (section 3.5).

**How the table was built** comes in W2: the field inverse, then XOR with four rotations and `63` (FIPS 197 section 5.1.1, sheet 5.8). It needs one more engine call, `AesKey.SboxBuild(byte)`, so that the numbers stay real.

### 2.4 Chapter 2: how the modes use the block

The chapter has one tab per mode. Each tab shows the blocks of a real message from this run, in a column, with **Lock** and **Unlock** paths. Each AES box opens chapter 1's step list on that box's real input.

| Mode | Message from this run | Goes into AES on lock | Comes out | On unlock |
|---|---|---|---|---|
| **ECB** | `TextEcb` on the `L1-use-ecb` fork. Else `PictureEcb`, first 4 rows of 257 | The data block | The cipher block | **Inverse AES** on the cipher block gives the data block |
| **CBC** | `TextCbc`. On the `L1-use-ecb` fork, `PictureCbc`, first 4 rows | The data block XOR the last cipher block (the IV at the start) | The cipher block | **Inverse AES** on the cipher block, then XOR the last cipher block |
| **GCM** | `TextGcm1` | A counter block: the nonce, then a count that starts at 2 | A key stream block, then XOR the data block gives the cipher block | **Forward AES** on the same counter gives the same key stream, then XOR. This engine checks the tag first. The rule is that no text comes out on a failure |

What each tab states, from sheet 5.12:

| | ECB | CBC | GCM |
|---|---|---|---|
| Promise | Hides single blocks only | Hides data, catches no edits | Hides data and catches edits |
| Starting value | None | A 16-byte IV. It must be **unpredictable**, and it is not secret | A 12-byte nonce. It must be **unique** under one key, and it is not secret |
| Padding | Yes. The 64-byte text gets one more block of 16 bytes of `10`, so it shows 5 blocks | Yes, the same | None. XOR uses only the key stream bytes it needs |
| Picture repeats in the run | 249 of 257 blocks in the golden trace | 0 of 257 | 0 of 256 |

**Why ECB and CBC reverse the steps and GCM does not.** This is the chapter's closing step:

- In ECB and CBC, the data itself goes through AES. To get it back, the receiver must undo AES. So it runs the inverse steps.
- In GCM, the data never goes through AES. AES locks a counter. The receiver makes the same key stream with forward AES. XOR twice gives the first value back.

| One 64-byte text, each side | Forward AES calls | Inverse AES calls |
|---|---|---|
| ECB, 5 blocks with padding | Sender 5 | Receiver 5 |
| CBC, 5 blocks with padding | Sender 5 | Receiver 5 |
| GCM, 4 blocks and no padding | Each side 6: 4 counters, 1 hash key, 1 tag mask | 0 |

`Gcm.cs` never calls `DecryptBlock` (sheet 5.2). The panel walks the 4 counters, and it names the other 2 calls. GHASH makes the tag, and it is out of scope for the walk. The panel shows the `GCM tag` result from the run's own `check.result` event.

**Live checks from the run.**

| Row field | Means |
|---|---|
| `wire: match` | The walk's cipher block equals the bytes in the run's `wire.sent` event |
| `wire: differs` | A fork changed the bytes. CBC unlock runs on the wire bytes, so the learner sees the damage: the spike's `L1-flip-cbc` run changed 16, 1, 0, 0, 0 bytes per block. That block turns to junk, the next block has the same bit flipped, and then it recovers. CBC raises no error. GCM shows the failed tag and no unlock, as the engine returns no bytes |

**Out of scope, named on the tab.** The modes page also lists CFB, OFB, and CTR, and it names XTS. CFB, OFB, and XTS are not in this course (grep of `src/NetSec.Core`: 0 files). CTR alone runs in lesson 8's SSH suite, and the panel points there. Lesson 1 runs counter mode only inside GCM.

### 2.5 Decision: ECB carries chapter 1

| Option | Readable letters at both ends of AES | Sent in the control run | Result |
|---|---|---|---|
| **ECB (chosen)** | Yes, before round key 0 and after the last step | Text: only under `L1-use-ecb`. Picture: yes | Best for seeing AES itself. The "teaching example" label states the gap |
| CBC | No. AES takes `input xor IV`, so the grid starts as junk | Yes, `TextCbc` | Truest to the run. Chapter 2 holds it, with a live wire match |
| GCM | No. AES takes a counter | Yes | Has no inverse path, so it cannot carry the decrypt walk |

Why ECB: Steve asked to see the letters come back. Chapter 2 then shows the inverse path on messages the control run did send: `TextCbc` and `PictureEcb`. So the label stays truthful and the inverse cipher has a real home in the same lesson.

**What would change my mind:** Jared or Steve reads the label and still finds the teaching example misleading. Then chapter 1 opens on `PictureEcb` block 1, and the letters move to the fork.

### 2.6 Word rules for the walk

From Jared's sheet. Echo can scan for these in `walk-gloss.json` and the tour.

| Write | Never write |
|---|---|
| "the input block", "the state" | "SubBytes replaces each byte of the plaintext" |
| "10 rounds in total" | "10 main rounds, then a final round" |
| "AES on one block reverses the steps". Name the mode when saying this | "Decryption reverses the steps", with no mode |
| "A matrix with a special multiply" | "matrix multiplication", with no note |
| "8 bits in, 8 bits out" | "each 4-bit chunk" |
| "GHASH makes the tag. AES supplies the hash key and the mask" | "AES makes the tag" |
| "The CBC IV must be unpredictable. The GCM nonce must be unique" | "Unique IV" for CBC, or one IV rule for all modes |
| "One block turns to junk, and the next has the same bit flipped. Then it recovers" | "A corrupted block affects subsequent blocks" |
| "This engine checks the tag first. No text comes out on a failure" | "GCM must check the tag first", as a rule of the standard |
| "Shows patterns" for ECB | "Vulnerable to cryptanalysis" for ECB |

### 2.7 Resolution semantics

| Question | Answer |
|---|---|
| Which key runs? | At 128 bits, the key the run used, read from the run's `aes.key` secret. At 192 or 256 bits, chapter 1 uses a practice key from `new SeededRandom(session.Seed ^ keyBits)` |
| When is it chosen? | At each query. The run's key is fixed when the run starts |
| Where is the choice visible? | `keySource` in the reply. The panel shows "This run's key" or "A practice key. It never ran in the lesson" |
| Which message feeds a mode? | The table in section 2.4: text when this run sent it in that mode, else the picture. The reply names it |
| A learner's own key? | The walk reads the key the run used, so `Mine` needs no separate path |
| No session, or a loaded replay? | `SESSION_NOT_FOUND`. A replay has no `LabSession`, so the pilot has no walk for it |
| Several identities? | One learner, one machine. This is the same non-goal as `modes-design.md` section 2.1 |

### 2.8 Controls, after a deletion pass

| Decision | Control |
|---|---|
| Which chapter | Two tabs |
| Which block (chapter 1) | One picker, 1 to 4 |
| Which key size (chapter 1) | One selector |
| Which mode (chapter 2) | Three tabs |
| Move through steps | Back, Next, and round chips to jump |
| See one byte's lookup | Click a cell |
| Open an AES box (chapter 2) | Click the box |

Cut: a play button, a speed slider, a separate encrypt/decrypt switch (decrypt follows encrypt in one step list), and a stand-alone S-box page.

## 3. Real data rule

### 3.1 The rule

Every state and table on screen comes from the C# engine at query time. The app holds no S-box, no round math, and no sample states. The app compares hex strings, indexes a table the Host sent, and formats. A clause scans `app/src` for the S-box bytes to enforce this.

### 3.2 How SubstituteAndMove splits

`EncryptBlock` and `DecryptBlock` keep `SubstituteAndMove`, unchanged. The walk path uses two small loops:

- `Sub(state, box)`: `state[i] = box[state[i]]`.
- `Move(state, map)`: `state[i]` takes the old `state[map[i]]`.

Both use the same `Sbox`, `InverseSbox`, `ShiftRowsMap`, and `InverseShiftRowsMap`. The walk calls the real `AddRoundKey`, `MixColumns`, and `InverseMixColumns`. So only those two loops and the order of the calls are new.

**The trade.** The round order now lives in two places, and a change to one needs a change to the other. That is a real DRY cost. I accept it, because a single path needs a branch per step in the path that lab traces and A2 use, and it still could not show the split without a second branch. Two guards pin the copies:

1. **At run time.** Each walk also calls the real method on the same input and throws `AES_WALK_DIVERGED` on any difference. Key expansion checks each word against `_roundKeys`. This is Jared's rule: the last value must match `EncryptBlock`.
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
    public readonly byte[] State;             // 16 bytes after this step, in r + 4c order
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
    public static byte[] SubstitutionTable();        // A copy of Sbox, 256 bytes
    public static byte[] InverseSubstitutionTable(); // A copy of InverseSbox, 256 bytes
  }
  public static class Gcm {                   // Added to Gcm.cs
    public static byte[] CounterBlock(byte[] nonce, int blockIndex);   // nonce, then 32-bit blockIndex + 2
  }
}
namespace NetSec.Labs {
  public enum AesFeedMode { Ecb, Cbc, Gcm }
  public enum AesPass { Forward, Inverse }
  public enum AesWireStatus { Match, Differs, NotSent }

  public sealed class AesBlockPair {          // Chapter 1, and an opened box in chapter 2
    public int KeyBits; public AesKeyWord[] KeyWords;
    public AesBlockWalk Forward; public AesBlockWalk Inverse;   // Inverse is null in GCM
  }
  public sealed class AesFeedRow {            // One block of a real message, lock and unlock
    public int Block;
    public byte[] Data;                       // The padded data block
    public byte[] Chain;                      // CBC: the IV or last cipher block. Else null
    public byte[] LockIn, LockOut;            // Into and out of forward AES
    public byte[] Cipher, Wire; public AesWireStatus Status;
    public AesPass UnlockPass;                // Inverse for ECB and CBC, Forward for GCM
    public byte[] UnlockIn, UnlockOut, Result;   // Null when a GCM tag failed
  }
  public sealed class AesFeedWalk {
    public AesFeedMode Mode; public string Message; public byte[] Starter;   // CBC IV or GCM nonce. Else null
    public int TotalBlocks, ForwardCalls, InverseCalls; public AesFeedRow[] Rows;
  }
  public static class AesWalks {              // Pure. Same input, same output. No session, no socket
    public static AesBlockPair Block(byte[] key, byte[] forwardInput, byte[] inverseInputOrNull);
    public static AesFeedWalk Feed(byte[] key, AesFeedMode mode, string message, byte[] plain, byte[] wireBody, bool tagPassed, int maxRows);
  }
}
```

`Gcm.CounterBlock` is new and pure. `CounterCrypt` stays as it is. The wire match catches a drift between the two. `Lesson01Aes.Pad` changes from private to internal, so the feed uses the lesson's own padding. Its bytes and the lab's trace stay as they are. `ErrorCodes` gains `AesWalkDiverged`, `WalkNotBuilt`, `WalkWaitingForWire`, `WalkKeySizeNotInRun`, and `WalkBadArgument`.

Language limits, checked by the spike: no optional parameters, no records, no expression bodies, no target-typed `new`. Types use only `byte[]`, `Buffer`, and `List<T>`.

### 3.4 Host routes and call path

`src/NetSec.Host/AesWalkRoutes.cs`, C# 14, net10. It joins `Program.cs` beside `SecurityRoutes.Map`.

```
GET /api/walk/aes/tables
GET /api/sessions/{id}/walk/aes/block?source=text|ecb|cbc|gcm&block=0..3&keyBits=128|192|256
GET /api/sessions/{id}/walk/aes/modes?mode=ecb|cbc|gcm
```

`source=text` is chapter 1. The other sources open a box in chapter 2, on the row's real input. Only `source=text` takes a `keyBits` other than the run's.

Call path for the two session routes:

1. The route reads `security.ShowKeys`. OFF returns 409 `KEYS_HIDDEN`, as the key log route does.
2. `sessions.Find(id)`. Null returns 404 `SESSION_NOT_FOUND`.
3. `session.Lesson != 1` returns 409 `WALK_NOT_BUILT`.
4. `AesWalkFacts.Read(session.After(0))` filters on `StoredEvent.Type` and `Message`, and parses only those shown lines. It takes `aes.key`, the `plain` of each `aes.message.sent`, the `wire` of the client's `wire.sent`, and the server's `GCM tag` check. `LabSession` holds no new state.
5. `AesWalks.Block` or `AesWalks.Feed` runs. For a practice key, the Host draws it first.
6. `AesWalkJson.Write` writes the reply. English stays out of Core.

`/api/walk/aes/tables` skips steps 1 to 5. The tables are public, so it stays open with Show keys OFF. It still passes `HostGuard`.

Why a session route takes an id and no bytes: a client cannot send a canned key or block, so the real data rule holds at the Host. The toggle also holds at the Host boundary, as in `modes-design.md` section 6.4.

Replies, trimmed. Every error carries `code`, `message`, `retryable`, and `requestId`.

```json
// /api/walk/aes/tables
{ "sbox": "637c777b...", "inverseSbox": "52096ad5..." }

// /block?source=text&block=0
{
  "source": "text", "block": 0, "blockCount": 4, "keyBits": 128, "rounds": 10, "keySource": "run",
  "inputHex": "50756d7020666f7572206973206f6b2e",
  "keyWords": [ { "i": 4, "previous": "...", "rotated": "...", "substituted": "...", "rcon": "...", "afterRcon": "...", "keyBack": "...", "word": "..." } ],
  "forward": { "input": "...", "output": "...", "steps": [ { "kind": "AddRoundKey", "round": 0, "state": "...", "roundKey": "..." } ] },
  "inverse": { "input": "...", "output": "...", "steps": [] },
  "wire": { "status": "notSent", "message": "TextEcb" }
}

// /modes?mode=gcm
{
  "mode": "gcm", "message": "TextGcm1", "starter": "e4f00aae0569f1494f973a46", "totalBlocks": 4,
  "forwardCalls": 6, "inverseCalls": 0,
  "rows": [ { "block": 0, "data": "...", "chain": null, "lockIn": "...00000002", "lockOut": "...", "cipher": "...",
              "wire": "...", "status": "match", "unlockPass": "forward", "unlockIn": "...00000002", "unlockOut": "...", "result": "..." } ]
}
```

| Case | Status and code |
|---|---|
| Show keys OFF, session routes | 409 `KEYS_HIDDEN` |
| Lesson other than 1, in the pilot | 409 `WALK_NOT_BUILT` |
| `keyBits` other than the run's, with a source other than `text` | 400 `WALK_KEY_SIZE_NOT_IN_RUN` |
| A step-mode run has not sent the message yet | 409 `WALK_WAITING_FOR_WIRE`, `retryable: true` |
| A bad mode, source, block, or key size | 400 `WALK_BAD_ARGUMENT` |
| A guard fired | 500 `AES_WALK_DIVERGED` |

### 3.5 Show keys OFF

**Decision: OFF closes the round states and keeps the public tables open.** Round 0's AddRoundKey gives `state = input xor key`, and the input is public here, so one state gives the whole key. Any later round key also gives the key, because the key schedule runs backward. A fingerprint per cell would teach nothing.

The walk's states lose their teaching with the toggle OFF. `modes-design.md` section 6.5 says each lesson keeps its comparison. That stays true for the lesson, because the panels of section 6.5 still run. The tab shows: "Show keys is off. Every step here gives away the key, so these steps stay closed. Turn Show keys on to walk them. The S-box table is public, and it stays open."

**The flip race.** This is the same class as PRs #140, #141, and #143. A reply can be in flight when the toggle flips, and it does not pass through `ShowKeysFence`. The fix sits in the app:

1. `walk.ts` holds a generation counter. The `security.show-keys` frame raises it, and the store clears the walk.
2. A reply whose generation is old is dropped.
3. A walk reply never enters a session file, `/events`, or a save.

Echo gets a clause for each of the three.

### 3.6 Spike output

Throwaway project in the session scratch folder. The walk file is compiled at `LangVersion 3`, beside a copy of `AesKey.cs` with `partial` added. It references the built `NetSec.Core.dll` to run the real lab with seed 20261105. Output below leaves out two single-block lines (CBC block 1 and `TextEcb` block 1), because the full-message lines cover them.

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
ECB text block: Pump four is ok. -> e968a3f7931ba4124a59f83fce569eec -> Pump four is ok.
real AesKey.EncryptBlock on the same block: e968a3f7931ba4124a59f83fce569eec
1,000,000 EncryptBlock: 493 ms. 10,000 WalkEncrypt: 60 ms
AES-128: rounds 10, 40 encrypt steps, 44 key words, about 5 KiB of hex for encrypt plus decrypt plus key words
AES-192: rounds 12, 48 encrypt steps, 52 key words, about 6 KiB of hex for encrypt plus decrypt plus key words
AES-256: rounds 14, 56 encrypt steps, 60 key words, about 7 KiB of hex for encrypt plus decrypt plus key words
S-box: 53->ed 50->53 00->63 ff->16; inverse ed->53
S-box: 256 entries, inverse undoes 256 of 256
table lookups equal the walk's byte swaps: 320 of 320 cells
Jared 5.3 round states: 5 of 5, output 1610a123c9fcfa091657149ba001aedb
PictureEcb (ECB): forward AES equals the wire on 257 of 257 blocks, inverse AES gives the data back on 257 of 257, distinct cipher blocks 8
TextCbc (CBC): forward AES of (data xor previous) equals the wire on 5 of 5 blocks, inverse AES then xor gives the data back on 5 of 5
TextEcb (ECB): forward AES equals the wire on 5 of 5 blocks, inverse AES gives the data back on 5 of 5, distinct cipher blocks 2
L1-flip-cbc: unlock from the wire bytes, changed bytes per block: 16,1,0,0,0
```

The 186 encrypt values and 186 inverse values come from FIPS 197 (2001 edition), appendix C. The comparison is strict, by position. "Jared 5.3" compares with his independent Python AES, which shares no code with the course. The walk file and the `AesKey` copy also compiled against the CF 3.5 references in `E:\dev\tools\netcf35-ref`, with 0 errors and 0 warnings.

Limits of the spike:

1. The walk file ran on the desktop CLR, on the copy of `AesKey`. It compiled for CF and did not run on it.
2. The feed logic in the spike is throwaway code, and `AesWalks` does not exist yet. No route, no app panel, and no Show keys path ran.
3. Same-seed runs give the same key, so the `TextEcb` check compares two runs.

**Which FIPS edition.** FIPS 197-upd1 (2023) is the source of record for the algorithm: section 3.4 for the state, 5.1 for the cipher, 5.2 for key expansion, 5.3 for the inverse. Its appendix B gives the AES-128 cipher example, and its appendix A gives the key tables. Upd1 removed the appendix C round values and points to NIST's example site. Its appendix D says the technical specifications did not change. So the inverse round values come from the 2001 edition, the same source `acceptance/vectors/SOURCES.md` already names. Jared should confirm this choice.

### 3.7 App shape

| File | Holds |
|---|---|
| `app/src/walk.ts` | `fetchAesBlock`, `fetchAesFeed`, `fetchAesTables`, the generation counter, and pure functions: `gridOf(hex)`, `changedCells(before, after)`, `rowColumnOf(byte)`, `describeStep(prev, step)`. No Vue, so a test can call each one |
| `app/src/walk-gloss.json` | The words for each step kind, chapter, and mode. A15 and A15a scan this file, so `docs_checks.py` gains it |
| `app/src/components/AesWalkPanel.vue` | Chapter tabs. Holds the two views below |
| `app/src/components/AesBlockWalk.vue` | Picker, grid, Back, Next, round chips |
| `app/src/components/SboxView.vue` | The 16 by 16 table, row and column lights, for both tables |
| `app/src/components/AesFeedView.vue` | One mode's rows, lock and unlock, the box link, wire status |
| `app/src/App.vue` | One more entry in the panel tab list, shown when the run holds `aes.key` |
| `app/src/tours/lesson-01.json` | Two new steps. One follows "ECB locks each block alone" and opens chapter 1. One follows "CBC and GCM hide the shape" and opens chapter 2. They land after #145 |
| `app/src/tour.ts` | A new `tryIt.expect` type, `walk-finished`, for those two steps |

Nancy owns the panels and their layout, and `feat/ux1-bytes` already changes the same area. So these panels start after her branch merges.

## 4. Effect on golden traces

**Echo re-records nothing.**

| Item | Effect |
|---|---|
| `acceptance/golden/{net10,cf}/lab-NN.ndjson`, 22 files | No change. The walk writes no `TraceEvent`, and the lab's behaviour does not change |
| `A17.mock.golden-trace-equal` | Stays green. It runs in every W slice as the proof |
| `A1.aes-*`, `A2` | No change. The real AES path has no edit |
| `session.save`, session files | No change. A walk reply is never stored |
| `acceptance/contract/` | Gains the types in section 3.3 and the routes in section 3.4 |
| Tour step counts | Lesson 1 gains two steps. `e2e/lesson-1.spec.ts` reads ids from the tour file, and its try-it actions gain the walk |

**The rule for later slices.** A walk is a query over the run's stored bytes. If a value exists only inside a run and no event holds it, the Host writes it on its own stream, as `<sessionId>/keys` does (`SessionManager.cs:238`). `GoldenClauses.Run` runs with no Host, so that stream never reaches a golden. Any slice that breaks this rule must name its goldens and ask Echo first.

## 5. Feel the difference: symmetric and asymmetric

Facts come from Jared's sheet, sections 1, 3, and 5.4 to 5.10. Steve's two pages set the order: how it works, what is hard about it, where it runs. **Key pairs act in lessons 3, 4, and 5. Lesson 7 adds the RSA box. Lessons 1, 2, and 6 are symmetric only.**

**The safe sentence, from sheet 5.10:** "A key pair does one of three jobs: agree on a secret, check a signature, or close a box around a small secret. Only the shared key locks the data."

### 5.1 Teaching order

| Stage | Symmetric (lesson 1) | Asymmetric (lessons 3, 4) |
|---|---|---|
| How it works | One shared key locks and unlocks. The walk shows the same round keys from first to last, then last to first | A pair: one private, one public. Three jobs, by key type (table below) |
| What is hard | Both sides must hold the same key, and a leak exposes all of it. 100 people need 4,950 keys, one per pair | Slow for bulk data. A public key alone names nobody, so lesson 4 ties it to a name |
| Where it runs | Every byte of real data, in lessons 1 and 5 | Setting up a key, and proving who you are, in lessons 3, 4, 5, 7, 8, 10 |
| How the two join | Lesson 5: the pairs set up the key, then AES-GCM carries the data | Lesson 5 |

### 5.2 Which picture fits which key

Sheet 5.10 governs. The mailbox picture on Steve's asymmetric page fits two of these keys, and a lesson must not use it for the others.

| Key | Job | Lesson | Picture | Avoid |
|---|---|---|---|---|
| X25519 | Agree on a secret | 3, 4, 5, 8, 10 | Two sides mix, and reach one secret | Any lock or box |
| ML-KEM | Close a box around a random value. Both sides hash the value into a key | 3, 5 | An open box that anyone can close and only the client can open | "Sends its key in a box", "locks the message" |
| Ed25519 | Sign and check | 4, 5, 8, 10 | A check against a signature | "Encrypts a hash", any lock |
| RSA | Lock one small secret, and sign | 7 | Lock and box, as in L7-S05 | Using it as the general story of TLS |
| Shared AES key | Lock and seal the data | 1, 2, 5 | One key on both sides | "Private-key encryption" |

### 5.3 What the learner does

| Lesson | The learner does | The learner feels | Engine call |
|---|---|---|---|
| 1 | Walks encrypt, then decrypt, and sees the same round keys in reverse order. Then flips one key bit and decrypts | One key does both jobs. A wrong key gives junk, and AES on one block gives no error | `WalkDecrypt` under the flipped key, W2. `source=text` gains `flipKeyBit` |
| 3 | Sees each side mix its own private part with the other's public share, and both reach one secret. Plays the eavesdropper: "mix" the two public shares, and sees a value that does not match. Opens the ML-KEM box step | Two strangers reach one secret. In X25519, that secret never crosses the wire | `X25519.Mult` on real bytes. Jared must approve the wording, because one failed try does not prove the hard problem |
| 4 | Key-pair bench. Sign with the private key, and check with the public key. Change one byte, and the check fails. Sign with `attacker-ed25519`, and the check fails. The bench offers no "sign with the public key" button, and the text says why | One owner can sign, and anyone can check. A tag from lesson 1 could come from either side. Only a signature points at the sender | `Ed25519.Sign`, `Ed25519.Verify`. New route `POST /api/walk/signature` |
| 5 | Sees which job each part did: hybrid exchange (asymmetric), certificate signature (asymmetric), AES-GCM records (symmetric). Then presses **Measure**: AES on 1 MB, and repeated Ed25519 signs and X25519 mixes | Pairs set up the key and the shared key carries the data. The speed gap is a number from this machine, labelled as such | `Modes.Ctr`, `Ed25519.Sign`, `X25519.Mult`. New route `POST /api/walk/speed` |
| 7 | L7-S05 points back to the bench: this is where a public key locks a secret, and it names RSA | Lock and sign are two different verbs | Tour text, W5 |

### 5.4 Lines that stay out

Sheet 5.9 lists them, and these three matter most:

1. "If the receiver can decrypt, the sender owns the private key." This is false. Anyone can lock with a public key.
2. "A signature encrypts a hash with the private key." This is false for Ed25519, the course's signer.
3. "Asymmetric is more secure than symmetric." They do different jobs.

## 6. Slices and build order

**Program design layer:** section 3.3 fixes types and signatures, section 3.4 fixes the routes and call path, section 3.7 fixes the app files. A builder picks local names only.

| Slice | Builds | Closing check | Owner |
|---|---|---|---|
| W0 | This doc. Jared's review. Echo's clauses, from sections 2 to 4, red | Clauses exist and fail with a named code | Richard, Jared, Echo |
| **W1a** skeleton | `AesKey.Walk.cs`, `Gcm.CounterBlock`, `AesWalks`, the three routes. No UI | FIPS, table, wire, BCL, toggle, and golden clauses pass on both builds. `tools/gate.ps1` green | Richard |
| **W1b** small section | `walk.ts`, `AesBlockWalk.vue`, `SboxView.vue`, chapter 1 at 128 bits, encrypt and decrypt | e2e: a learner reaches `Pump four is ok.` by Next alone. A clicked cell's lookup equals the next state, both tables. Grid order clause. S-box scan | Nancy |
| **W1c** | `AesFeedView.vue`, chapter 2 with ECB, CBC, GCM. Key sizes, the flip guard, two tour steps, gloss | e2e on wire match per mode and on the flip. A15, A15a by a reader who did not write it | Nancy, Richard |
| W2 | `AesKey.SboxBuild(byte)` and "how the table was built". `flipKeyBit`. One-bit-flip spread count (4 bytes after round 1, 16 after round 2) | FIPS 5.1.1 worked example for `53`. Spread count against Jared's values | Richard, Nancy |
| W3 | Lesson 3 try-it, lesson 4 bench | Clauses on each check result | Richard, Nancy, Jared on wording |
| W4 | Lesson 5 record walk and speed bench | Record walk equals the wire. The number's label names the machine | Richard, Nancy |
| W5 | Lessons 2, 6 (section 1.1), 7, 8 queries, one PR each | A reference check per lesson, from Jared. Lesson 6: each replayed PIN key equals the run's | Richard, Jared |
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
| S-box | Both tables equal FIPS Tables 4 and 6 on all 256 entries. `53` gives `ed`, and row `e`, column `d` of the inverse gives `53`. The route answers with Show keys OFF |
| S-box view | A clicked cell's row, column, and table value equal the next state's cell, on SubBytes and InvSubBytes |
| Real run | Key and block from a live session's trace, with the BCL as referee on the walk's output |
| Modes | `match` on every row: `TextGcm1` 4, `TextCbc` 5, `PictureEcb` capped rows, `TextEcb` 5 on the fork. `unlockPass` is inverse for ECB and CBC, forward for GCM. Call counts per section 2.4 |
| Damage | `L1-flip-cbc` gives `differs` and the 16, 1, 0, 0, 0 pattern. `L1-flip-gcm` gives `differs`, a failed tag, and no unlock bytes |
| Label | A control run's `source=text` reply says `notSent`, and the panel shows the teaching-example label |
| Real path | `WalkEncrypt` equals `EncryptBlock` on 10,000 random inputs |
| Toggle | OFF gives 409 `KEYS_HIDDEN` on both session routes. A flip drops an in-flight reply. No state reaches a session file |
| No app math | No S-box bytes under `app/src` |
| Grid order | Row r, column c shows byte `r + 4c`, on every state. On the first view, the first column reads `Pump` and cells fill in position order 0 to 15 |
| Step order | A walk by Next alone meets the section 2.1 steps in order |
| Words | The section 2.6 "never write" lines are absent from `walk-gloss.json` and the lesson 1 tour |
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

**The arithmetic.** One learner, at most about 1 walk query per second while picking blocks. A block reply is about 5 to 7 KiB, and a feed reply holds at most 5 rows. The tables reply is 1,024 hex characters, fetched once. A walk costs about 6 microseconds in this test environment, against about 0.5 microseconds for `EncryptBlock`. Storage over three years is zero, since nothing is stored. So the design uses no cache, no streaming, and no per-step request. One reply holds the whole walk, and Next is a local move.

**Gem catalog.** I read `E:\dev\MMP.ProgrammingGems\INDEX.md`.

| Gem | Use |
|---|---|
| `decide-at-authoritative-boundary` | Applies. The Host decides the toggle and the facts, once, at the route. Mark `AesWalkRoutes` |
| `server-replaces-never-merges` | Applies. The app replaces the whole walk on each reply and clears it on a flip. Mark `walk.ts` |
| A new gem? | No gem covers "an instrumented twin of a hot path, checked against the real path on every call". One use site so far. I record it as a candidate at W5, with Jared as SME, if the second walk type uses it too |

**CUPID, under pressure.** Predictable is the property most at risk, because a twin path can drift. The run-time guard answers that. Composable holds: `AesWalks` is pure, and lessons 5 and 7 reuse it. Domain-based holds: the types use the FIPS step names. Complexity hotspots: `describeStep` wants a lookup by step kind, and each Vue file stays thin because `walk.ts` holds the logic. SOLID adds nothing here.

## 8. Non-goals

1. No walk of GHASH, SHA-256 rounds, or the X25519 ladder in the pilot.
2. No CFB, OFB, or XTS. No CTR tab in lesson 1.
3. No walk on a loaded replay or an OS transport session.
4. No change to `EncryptBlock`, `DecryptBlock`, or `CounterCrypt`.
5. No claim that this AES is production AES. `AesKey.cs:8` already says that table lookups can leak through a CPU cache, and the panel says so too.

## Disposition

Ready for Jared's review on the crypto wording and sections 2.4, 2.5, 3.5, 3.6, and 5, and for Echo's clauses. Do not start W1a until both are done.
