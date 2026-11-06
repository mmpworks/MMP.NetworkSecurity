# MMP.NetworkSecurity: walkthrough design

Author: Richard. Date: 2026-11-06. Revision 14, adding the GCM stream view for W1c. Status: design only, for Jared's check and Echo's clauses. No product code.

Sources of facts: FIPS 197, the engine, and Jared's sheet `E:\dev\ns-lesson1-facts.md`. Steve's web pages set depth and teaching order only (section 2.1).

## The two changes I would make

1. **Add three Host queries that run a new walk path beside the real AES path.** They read the key and the bytes of the real lesson 1 run. They add no trace event, so all 22 golden traces stay as they are.
2. **Teach AES in two chapters, in this order.** Chapter 1 opens one block: each step in order, for encryption and decryption, with the S-box lookup shown byte by byte. Chapter 2 shows how ECB, CBC, and GCM feed blocks through AES, with lesson 1's real messages. Chapter 2 is where the learner sees why ECB and CBC need the reverse steps and GCM does not.

## Conclusion

1. The walk has a working spike. It matched all 372 FIPS 197 round values. ECB, CBC, and GCM each matched the wire on every block of a real lesson 1 run (section 3.6).
2. `EncryptBlock` and `DecryptBlock` do not change. The split of SubBytes and ShiftRows lives only in the walk path.
3. The S-box tables come from the engine by a public route. With Show keys OFF, the tables and the modes walk stay open, and the round states close (section 3.5).
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

**The shape on screen.** One chain of real values, top to bottom, in numbered steps with one input and one output each, ending in the digits the learner can read. The lab's sale 3 is counter binary 11, so it shows a two-step walk. The screen uses the run's real keys.

**A checked test case, off screen.** Jared computed this chain on the course code. X9's free test vector PDF lists the four key values marked "X9". W5 pins it in a test.

| Step | Value |
|---|---|
| Base key | `FEDCBA9876543210F1F1F1F1F1F1F1F1` |
| Key id | `1234567890123456` |
| Initial key (X9) | `1273671EA26AC29AFA4D1084127652A1` |
| Counter 5 is binary 101, so bit 2 is on: counter 4 (X9) | `0EEFC7ADA628BA68878DA9165A8A1887` |
| Then bit 0 is on: counter 5 (X9) | `C2A7AC328A5DA2D6002D62465BFC028B` |
| PIN key for counter 5 (X9) | `35A43BC9EFEB09C756204B57E3FB7D4D` |
| KSN | `123456789012345600000005` |
| PIN block, random `0102030405060708` | `8C1C1152B1543E9D70CA145336E264E2`, opens to `1234` |

**Words on screen.** Older DUKPT pages call a single "session key" a PIN variant, with XOR masks. Those are TDES details, and they stay out. "Erased" keeps the existing tour line: erasing clears a register in place, and a managed heap can keep copies.

**How the query stays real.** It builds a new `DukptPinPad` from the run's `dukpt.initial` bytes and key id, steps it to each sale, and reads its registers. `HeldKeys()` gives no register numbers, so W5 adds a read that does. Each replayed PIN key must equal the run's `dukpt.pinKey.<c>`, or the query throws `WALK_DIVERGED`. The replay writes no event, so the golden holds.

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
| 3 | The key schedule: the key as words, then the expanded table, built one word at a time. The key size sets the rounds: 10, 12, or 14 in total | Section 2.2b |
| 4 | AddRoundKey with round key 0. This comes before round 1, and it is not a round | Section 2.2 |
| 5 | SubBytes, with one byte traced through the S-box | Sections 2.2, 2.3 |
| 6 | ShiftRows | Section 2.2 |
| 7 | MixColumns, with one real multiply and the field definition | Sections 2.2, 2.2c |
| 8 | AddRoundKey | Section 2.2 |
| 9 | Repeat for the other rounds | Round chips |
| 10 | The last round, with no MixColumns | Section 2.2 |
| 11 | Decryption, step by step, with the inverse table | Sections 2.2, 2.3 |
| 12 | Modes: ECB, CBC, GCM, with lock and unlock for each | Section 2.4 |

Each step in chapter 1 also moves, as section 2.2a sets out, and carries one "why" line, as section 2.2d sets out.

Round 1 shows each step in full. So step 5 opens the S-box view by itself on the first SubBytes, with the first cell selected. Later rounds keep it one click away.

Jared's sheet sections 5.7, 5.9, 5.11, 5.13, and 5.14 list the lines on these pages that a lesson must not copy.

### 2.2 Chapter 1: inside the block

The learner runs lesson 1 and opens the **AES walk** tab.

**The first view teaches the grid.** A reader learns the fill order here, so this view must get it right.

1. The text shows split into 4 blocks of 16 bytes. All four hold the same letters, and the panel says so. So chapter 1 walks block 1, and it offers no picker, because a picker would change nothing here. The learner picks a block in chapter 2, where each block goes a different way, by opening its AES box.
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
| Key schedule | The key as words, then the expanded table, built one word at a time (section 2.2b) | The key makes 11 round keys for AES-128 (13 for 192, 15 for 256) |
| Encrypt | AddRoundKey 0. Rounds 1 to 9: SubBytes, ShiftRows, MixColumns, AddRoundKey. Round 10: SubBytes, ShiftRows, AddRoundKey | The first SubBytes sees letters XOR round key 0. It never sees bare letters |
| Decrypt | AddRoundKey 10. Rounds 9 to 1: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns. Last: InvShiftRows, InvSubBytes, AddRoundKey 0. The grid reads `Pump four is ok.` | The same key, with the round keys from last to first. This is FIPS 197 section 5.3 order, and the only order that works with these round keys (sheet 5.1) |

Each state shows as a 4x4 grid. A cell shows its hex byte, and its letter when the byte is printable. The fill order comes from FIPS 197 section 3.4: `s[r, c] = in[r + 4c]`. A row-first grid would make ShiftRows look wrong, so a clause pins this on the first view and on every state.

Key size: a selector offers 128, 192, and 256 bits. The block stays 16 bytes. Only the rounds change.

What each step says:

| Step | What it says, from the real bytes | Picture |
|---|---|---|
| AddRoundKey | Each byte is XORed with the round key. This is the only step that uses the key. It is its own inverse. The step button names the key: "AddRoundKey 1", and "AddRoundKey 0" in round 0. In decrypt the number counts down the same way. The number is the step's `round` | State, round key, result |
| SubBytes | Each byte is swapped with the S-box table. The table is public and fixed | Before and after, plus the S-box view (section 2.3) |
| ShiftRows | Row 0 stays. Rows 1, 2, 3 slide left by 1, 2, 3 | Before and after, rows marked |
| MixColumns | Each column is replaced by a mix of its 4 bytes, by a matrix with a special multiply. Ordinary multiply gives wrong bytes | The selected column before and after, and the matrix 2, 3, 1, 1. The app runs no math |
| InvShiftRows | Rows 1, 2, 3 slide right by 1, 2, 3 | Before and after |
| InvSubBytes | Each byte swaps back with the inverse table | S-box view, on the inverse table |
| InvMixColumns | Each column is unmixed, by the matrix 14, 11, 13, 9 | The selected column before and after |
| KeyExpansion | Each word comes from the word before it and the word one key back. Every Nk words, it also rotates, swaps by S-box, and takes a round constant. AES-256 adds one more S-box swap | One row of the FIPS 197 appendix A table |

### 2.2a The block animation

Steve's ask: see the 16 bytes change at each stage.

**Rule: the animation only moves between states the engine already returned. The app computes no byte.** Motion is decoration between two engine states, and each step lands on its engine end frame.

| Step | What moves | End frame |
|---|---|---|
| AddRoundKey | In order: the round key grid fills on the right, column by column, and holds with the block unchanged. It then slides over the block, each byte changes one at a time, and the key returns. An AddRoundKey that runs from a Start view skips the fill, because that view already shows its key. That is round 0 on encrypt, and round Nr on decrypt. Every other AddRoundKey fills, including one reached by a round chip, and decrypt's AddRoundKey 0 | Step's `roundKey`, then the engine state after AddRoundKey |
| SubBytes | Each cell flips to its new byte, one cell at a time on the first pass, then all cells at once | Engine state after SubBytes |
| ShiftRows | A smooth roll, one row at a time, like a ticker tape. Row 0 stays. Rows 1, 2, 3 rotate left by 1, 2, 3: bytes leave the left edge and enter at the right edge. No fade and no lift | Engine state after ShiftRows |
| MixColumns | One column at a time lifts, its 4 bytes join, and 4 new bytes come out | Engine state after MixColumns |
| Inverse steps | The same motion, in the inverse direction | Engine state after the inverse step |

| Detail | Rule |
|---|---|
| Where a byte came from | Each cell shows a small mark with its position before this step, 0 to 15. The marks reset at each step, because a byte has no single source after MixColumns |
| Which way ShiftRows moves | The engine's `ShiftRowsMap` and `InverseShiftRowsMap` come from the tables route (section 3.4), so a motion cannot disagree with the real map |
| Next and Back | They land on the same states as without animation. A click during a motion jumps to the end frame. A Back during a roll or a key fill leaves no strip, no flying byte, no mark, and no hidden cell |
| Start view | The right-hand grid shows the round key the next step uses, in place of "Before this step": round key 0 at the start of encryption, and round key Nr at the start of decryption. Next then runs the AddRoundKey motion from it. **The decrypt Start view is a stop in the one step list:** after encrypt's last step, Next lands on it with no motion, and the block shows the ciphertext. The app builds both Start views from the reply, so `steps` holds no extra entry. Show keys OFF closes it, as the block walk closes |
| `prefers-reduced-motion` | Each step jumps to its end frame |
| Show keys flips OFF during a motion, or during a pause | The timeline stops, and the walk clears (section 3.5) |
| Library | None. CSS transforms and one small composable, `useWalkTimeline`. I would add a library only if a transform cannot do the MixColumns join |

**ShiftRows colours.** During the roll, only the bytes that wrap take the highlight colour: 1 in row 1, 2 in row 2, 3 in row 3. The others stay normal, and the colours stay on the end frame. On ShiftRows they form a staircase at the right, and on InvShiftRows the bytes wrap the other way, so it forms at the left:

```
ShiftRows   InvShiftRows
. . . .     . . . .
. . . X     X . . .
. . X X     X X . .
. X X X     X X X .
```

The app marks a cell from the shift map the tables route sends, and it reads no byte value to do so.

**ShiftRows words on screen:** "Row 0 stays. Rows 1, 2 and 3 rotate left by 1, 2 and 3 bytes. The name says shift, but no byte is lost: FIPS 197 calls it a cyclic shift, the same idea as a rotate left (ROL)."

For tests: a clause reads end frames under reduced motion, so no test waits on a timer. The pause clauses are the one exception, because they test motion itself.

**Pause and resume (Steve's rule, for every walk motion).** Steve's words: "we should have pause and resume capability. That allows a user to pause and manually spend time on one part of the math without having to replay it."

| Action | Result |
|---|---|
| Pause | Everything freezes in place, including a byte in mid-flight. Nothing jumps to the end of the word or the step |
| Resume | The motion carries on from that spot, with the time it had left |
| Next or Back while paused | The current motion ends, then the button acts. Play stops too. This differs on purpose from a click during a running motion, which only jumps to that motion's end. A learner who paused has finished with that motion, so one press moves on |
| A tap that changes the view while paused (a byte, a column, a word, a round chip, a selector) | The current motion ends, then the tap acts. Play stops too |
| Hover or focus while paused | Tips and spec cards still work. They read the same values as when the walk is stopped |
| Speed while paused | The new speed applies from the next motion |

The one button reads by state:

| State | Button |
|---|---|
| Nothing runs | Play |
| Anything runs, even from a single Next | Pause |
| Frozen | Resume |

Play still stops at the end of a round or a grid. Only Pause freezes in mid-motion. This replaces the earlier words, where Pause stopped at an end point.

**One clock.** `useWalkTimeline` owns every timer and every running animation. A view asks it for a delay and never calls `setTimeout` itself. Pause clears each timer and records the time left, then pauses each running animation under the walk's root element. Resume starts both again. A motion is CSS or Web Animations only, because the clock reads the animation list under the root, and a `requestAnimationFrame` flyer would escape both Pause and the clauses. A flying byte or bit mounts inside that root, so Pause reaches it, and Pause leaves the rest of the app running. With reduced motion, a step lands at once, so Pause freezes only the wait between steps.

### 2.2b The key schedule part

Steve's ask: how the key schedule is created. FIPS 197 section 5.2 is the source of record. None of Steve's five videos walks it, by the lead's reading. This part comes before the first AddRoundKey.

**View 1, the key and the expanded table.**

1. The original key shows as its words: `w0` to `w3` at AES-128.
2. The whole expanded table shows as one grid of 16 cells per round key: 11 grids at AES-128. Each column of a grid is one word, so the columns fill in the same order as the block (section 2.2).
3. Each cell looks like a block cell: its byte position at top left, hex in the centre, its word name at lower left, and no letter at lower right, because key bytes are not text.

The byte position runs through the whole table, 0 to 175 at AES-128. `w4` is positions 16 to 19, in round key 1's first column.

| Key | Nk (key words) | Rounds | Round keys, so grids | Words | Byte positions | Round constants used | Where the key ends |
|---|---|---|---|---|---|---|---|
| AES-128 | 4 | 10 | 11 | 44 | 0 to 175 | 10 | The end of round key 0 |
| AES-192 | 6 | 12 | 13 | 52 | 0 to 207 | 8 | The second column of round key 1 |
| AES-256 | 8 | 14 | 15 | 60 | 0 to 239 | 7 | The end of round key 1 |

**At AES-192 and AES-256, the key runs past round key 0.** The grids stay one per round key, because each grid is what one AddRoundKey uses. A band marks the key's words across the grids: `w0` to `w5` at AES-192, and `w0` to `w7` at AES-256. Those cells start filled, and the panel says: "The first 6 words are the key, so round key 1 starts with key bytes." At AES-256 it says: "The first 8 words are the key, so round key 1 is all key bytes." The build starts at the next column: `w6` at AES-192, and `w8` at AES-256.

**View 2, build one word.** The first Nk words are the key itself. Each later word comes from two earlier words: the one before it, and the one Nk back. Every Nk words, the word before it first passes through three steps. Next and Play build one word at a time.

| Moment | On screen |
|---|---|
| A word builds | The word before it and the word Nk back light up in the table. Each one matches its stage row by colour, and the stage row also names it, such as `w3` and `w0`, so colour is never the only sign |
| Play | Stops when a grid fills, by the rule of section 2.8. Press it again for the next grid. A round chip jumps to a grid |
| Tap a built word | Its stage rows open, and the two words behind it light up. A word not yet built does nothing |
| A key word | It has no stage rows, so a tap says "This word is part of the key" |

Worked example, the FIPS 197 appendix A key `2b7e1516 28aed2a6 abf71588 09cf4f3c`. The app shows the run's own key, with the same steps.

| Stage | Bytes | Field in the reply |
|---|---|---|
| w3 | `09cf4f3c` | `previous` |
| RotWord | `cf4f3c09` | `rotated` |
| SubWord (same S-box) | `8a84eb01` | `substituted` |
| XOR Rcon 1 (`01000000`) | `8b84eb01` | `rcon`, `afterRcon` |
| XOR w0 (`2b7e1516`) | `a0fafe17`, which is w4 | `keyBack`, `word` |

**AES-256 only:** at `i mod 8 = 4`, the word before passes through SubWord alone. The panel says so when the learner picks 256.

**Each word's panel shows the test that decided it (Steve's item, W1b).** FIPS 197 section 5.2 picks a word's steps by dividing its index by Nk.

| The word | Words on screen, by example |
|---|---|
| Has `rotated` | "18 ÷ 6 = 3, no remainder, so w18 rotates. It is rotation 3, so it takes round constant 3: 04." |
| Has `substituted` and no `rotated` | "12 ÷ 8 leaves 4, so w12 gets the S-box step only. AES-256 adds this rule." |
| Has no stages, past the key | "19 ÷ 6 leaves 1, so w19 is plain: no rotation." |
| Part of the key | "w3 is part of the key, so nothing is calculated." |

**A new field: yes, on each `keyWords` row.** The row gains `divisor`, `quotient`, and `remainder`, and the app prints them. They are not layout, which the app can work out from `i`. They are the rule itself, so an app that worked them out would be a second copy of the engine's branch, and the sentence could then disagree with the word it describes.

The app picks the sentence from which stages the row holds, so the sentence cannot name a step the engine did not run. "Round constant 3" prints `quotient`, and "04" prints the first byte of the row's `rcon`. At AES-192, a word with remainder 4 is plain, and its sentence says so: "10 ÷ 6 leaves 4, so w10 is plain: no rotation."

**A new word builds byte by byte.** For byte j of word i:

| Moment | On screen | Value from the reply |
|---|---|---|
| 1. Light the sources | Byte j of `w(i - Nk)` lights up in the table. So does the source byte of `w(i - 1)`, or byte j of the phantom column when the word has one. Both also light in the original key line when they are key words | Position arithmetic |
| 2. The stages | The stage rows show. In the `previous` row, the source byte lights. In each row after RotWord, byte j lights | `previous`, `rotated`, `substituted`, `afterRcon`, `keyBack` |
| 3. The equation | "2b XOR 8b = a0", with each value's bits below it | `keyBack[j]`, the last stage's byte j, and `word[j]`. The app prints these, and it computes no XOR |
| 4. The answer flies | The byte flies to its cell, and the column fills one cell at a time | `word[j]` |

**The source byte.** RotWord moves each byte left, so on a word that passes through RotWord, byte j of the stage comes from byte `(j + 1) mod 4` of the word before. On every other word, it is byte j. The last stage is `afterRcon` on a RotWord step, `substituted` at the AES-256 `i mod 8 = 4` step, and `previous` otherwise.

The stage row for RotWord reads "RotWord: rotate one byte, up this column". With reduced motion, each word lands whole, and Back mid-word leaves no marks.

**The phantom column (Steve's item, W1b).** A word that transforms a copy of the word before gets a phantom: a copy of that column, lifted above the base. RotWord words have one, and so do AES-256's SubWord-only words. Plain words, such as w5, show none. The base column never changes, and the learner can see that.

| Moment | The phantom shows | Value from the reply |
|---|---|---|
| 1. It lifts | A copy of `w(i - 1)`, above the base column | `previous` |
| 2. It rotates (RotWord words only) | Each byte moves up one place, and the top byte wraps to the bottom | `rotated` |
| 3. It flips through the S-box | Each byte changes to its S-box byte | `substituted` |
| 4. It flips with the round constant (RotWord words only) | The top byte changes | `afterRcon` |
| 5. It lines up | Row by row with the new word. Byte j of the phantom combines with byte j of the word back | The last stage, and `keyBack` |
| 6. It flattens | It settles down and goes when the column is done | None |

Panel words, with the word names from `i`:

1. RotWord word: "RotWord works on a copy of w7, so w7 itself does not change. The copy moves up one byte, and the top byte wraps to the bottom. All 4 bytes of w8 then use this one finished copy."
2. SubWord-only word: "SubWord works on a copy of w11, so w11 itself does not change. All 4 bytes of w12 then use this one finished copy."

| Case | Rule |
|---|---|
| New reply fields | None. The stages already hold every value, and the app computes none |
| Pause | Holds the phantom in place, as section 2.2a sets out. It is a CSS or Web Animations motion inside the walk's root |
| Back, a round chip, or Show keys OFF | Removes the phantom, with none left behind |
| Reduced motion | No phantom. The word lands whole, and the stage rows and the panel words still show |
| A tap on a built word | Opens its stage rows, with no phantom, because the phantom belongs to the build |

**The reply needs no other new field.** `keyWords[]` already has every row by `i`, and each row holds `word`, `previous`, `rotated`, `substituted`, `rcon`, `afterRcon`, and `keyBack`, beside the 3 numbers of the word test above. Grid, column, cell, and byte position come from `i` by layout: `i / 4`, `i % 4`, and `4i + r`. The two words to light are `i - 1` and `i - Nk`, with Nk from the tables route's size table. That is position arithmetic, and the app reads no byte value to do it. A clause holds it: the bytes in the lit cells must equal `previous` and `keyBack`.

**Rcon row.** `01 02 04 08 10 20 40 80 1b 36`. Each value is the one before it, doubled in the field. Ordinary doubling of `80` gives `100`, which does not fit in a byte. Field doubling gives `1b`. This row is the first place the learner meets the field in real use. The row comes from the tables route, because the app holds no crypto values.

**The round constants animate (Steve's item, W1b).** A "Play the doubling" button builds the list from `01`, one doubling at a time. Next takes one doubling.

| Part | On screen | Value from the tables route |
|---|---|---|
| The list | The 10 values, filling from `01` | `rcon` |
| One doubling | The same bit rows as the matrix view (section 2.2i) | `rconSteps[n]`: `from`, `shifted`, `reduced`, `to` |
| `80` to `1b` | Bit 8 breaks away and flies off, and the XOR 1b row shows, as section 2.2i sets out | `rconSteps[7]`, where `shifted` is `100` and `reduced` is true |
| Values this size does not use | Dimmed, with the words "AES-192 uses 8 of these 10." | `rconUsed`: 10, 8, 7 |

Play builds all 10 values at every key size, and stops at the end of the list. The mock stops at the size's used count, so AES-192 and AES-256 never reach `80` to `1b`. Steve asked to see that step, so the design keeps it for every size, with the values past the used count dimmed.

Words at the start: "The list starts at 01. No key goes in, so every AES key uses this same list."

**A compact row in the key schedule side panel** shows the same 10 values and lights the one the current rotating word uses. The app finds it by comparing the first byte of that word's `rcon` with the list, which it can do because the 10 values differ. A SubWord-only word and a plain word light none.

Pause and Resume follow section 2.2a. With reduced motion, each doubling lands at once. Show keys OFF stops the motion, as section 3.5 sets out. The list holds no key byte, so the tables route still answers with Show keys OFF.

**A new field: yes, `rconSteps` on the tables route.** The app runs no math, so the engine sends each doubling. It uses the `AesDoubling` shape that MixColumns terms use, so the bit rows read one shape. The list has 10 values, so it has 9 steps.

**Words on screen:**

1. "Each round gets its own key."
2. At AES-128 only: "Round keys are key material. Anyone who learns one round key can run this table backward and get the key." The lead's script ran this from round key 10 and got the key back. This line stays at 128, because AES-192 needs 6 words and AES-256 needs 8.
3. "Decryption uses the same round keys, from last to first."

### 2.2c The finite field

Steve's ask: define a finite field. The panel states the definition and shows one real multiply.

**Definition on screen, in this order:**

1. "A field is a set of values with add, subtract, multiply and divide, where every answer stays in the set. Only divide by zero is not allowed. They follow the usual rules of arithmetic."
2. "A finite field has a fixed number of values. Another name for it is a Galois field. The field that AES uses has 256 values, one for each byte. Its name is GF(2^8)."
3. "Add is XOR."
4. "Multiply treats each byte as a polynomial, multiplies without carries, and reduces the result by `x^8 + x^4 + x^3 + x + 1` (`11b` in hex). So the answer always fits in a byte."
5. "Every value except zero has an inverse. So multiplying by any nonzero value can be undone."

A fixed number of values alone does not make a field, so the panel states both rules. FIPS 197 does not define a field (section 4, footnote 1) and sends the reader to textbooks. These lines are our wording, and Jared read them against the FIPS arithmetic.

| Place | What the learner sees |
|---|---|
| Rcon row | `80` doubled gives `1b` |
| MixColumns | One real multiply from the run's selected column, with its reduction shown |
| InvMixColumns | The same, with factors 14, 11, 13, 9. Each needs 3 doublings |
| S-box, "How the table was built" | Starts from the byte's inverse in this field. It stays in W2 and links back to the definition |

Worked example for the words and the clause. Column `d4 bf 5d 30`, from FIPS 197 appendix B round 1.

| Term | Field result | Ordinary result |
|---|---|---|
| `2 x d4` | `b3` | `1a8`, too big for a byte |
| `3 x bf` | `da` | `23d`, too big for a byte |
| `1 x 5d` | `5d` | |
| `1 x 30` | `30` | |
| XOR of the 4 terms | `04` | |

The full column comes out `04 66 81 e5`. The inverse takes it back: `14 x 04` is `38`, `11 x 66` is `b7`, `13 x 81` is `d7`, `9 x e5` is `8c`, and their XOR is `d4`.

**"The app runs no math" stays.** The engine returns the terms, and the app only prints them (section 3.3).

### 2.2d Why each step exists

Each step's panel adds one "why" line. FIPS 197 does not use the words confusion and diffusion. The meanings below follow Shannon 1949, section 23, which Jared read. Tying each step to one word is common teaching and not Shannon's, so the panel says "often called" and states no source for that mapping.

| Term | Meaning on screen |
|---|---|
| Confusion | The link between the key and the locked bytes is made very hard to follow |
| Diffusion | The patterns in the message spread out across the locked bytes |

| Step | Why line |
|---|---|
| AddRoundKey | The key enters here and nowhere else |
| SubBytes | It breaks straight-line math, and confusion rests on that. The table is public and holds no key, so it needs the key steps around it |
| ShiftRows | Diffusion between columns. Without it, each column would stay on its own |
| MixColumns | Diffusion inside a column. Each output byte depends on all 4 input bytes |

One measured line sits apart from the definitions, because a one-bit test is not what either word means: "In one test, one changed input bit changed 4 bytes after round 1, all 16 bytes after round 2, and 54 of the 128 output bits at the end." W2's one-bit-flip count shows these numbers from the engine on the run's own block. W1 states the test as a test.

**What stays out.** No robots, no 3D, and no video style copy: our own 2D grid and our own colours. No frames, captions, or drawings from the videos, which are leads for order and teaching ideas. No claim that AES hardware instructions are "impervious", which is wider than we can source.

### 2.2e Tap a byte, and jump to a round

These two ideas come from CrypTool's "AES (step-by-step)" page. We take the ideas and no code.

**Jump to a round.** The round chips of section 2.8 already do this, in encrypt and decrypt. Play continues from the round the learner jumps to.

**Tap a byte (W2).** The learner taps a byte in any state. Earlier states light up the bytes it depends on, back to the input block. It ends at each round key byte too, and it stops there, because a walk back through the key schedule belongs to section 2.2b.

| Step | A byte in this cell depends on |
|---|---|
| AddRoundKey | The same cell, and the same cell of the round key |
| SubBytes, InvSubBytes | The same cell |
| ShiftRows, InvShiftRows | The cell the shift map names |
| MixColumns, InvMixColumns | All 4 cells of its column |

**No math in the app.** The engine sends this rule in the tables route as `dependsOn`, one list per step kind and cell. The app follows those lists backward. That is a graph walk, and it reads no byte value. The rule holds no key, so it stays open with Show keys OFF. The grids it lights stay closed.

**A clause checks the rule against the real cipher.** Change one input byte: a state byte outside its set must never change, and a byte inside its set must change for some value. The spike ran this on 10,240 cases, with 0 faults of either kind. A cell after round 1's ShiftRows depends on 1 input byte. Cell 0 after round 1's MixColumns depends on 4, and after round 2's on all 16.

**Why W2, and not W1b.**

1. W2 already holds the one-bit-flip count, and tap-a-byte is the same lesson: diffusion. They share the clause's flip test.
2. W1b ends in Steve's first look at the block walk. A tap there would mean two things on a SubBytes cell (the S-box lookup, and the dependency). I would rather settle that gesture once with Steve's reaction in hand.
3. Nothing in W1a or W1b depends on it, and the rule adds one call to `AesKey`.

**What would change my mind:** Steve asks for it during his W1b look, or the new look gives each gesture its own place.

### 2.2f Binary on hover (W1b)

Steve's ask: see any hex value in binary.

**Hover or keyboard focus on any hex value shows its bits.** A touch screen uses the same tip on a long press, because a tap already has a meaning on a cell.

| Target | The tip shows |
|---|---|
| Any hex value | Its bits in two groups of 4, such as `53  0101 0011`. A longer value, such as a word or H, shows one line per byte, up to 16 lines, then "+ n more bytes" |
| A state cell, on SubBytes, MixColumns, AddRoundKey, and their inverses | Before and after the step, changed bits marked, and a count: "3 of 8 bits changed" |
| A state cell, on ShiftRows and InvShiftRows | On rows 1, 2, 3: the position it came from, and "This byte moved. No bits changed." On row 0: "This byte stayed. Row 0 does not shift." A same-position compare would show a false change, so the tip compares nothing here |

**The app only formats bytes the engine sent.** The tip turns a hex string into a bit string and compares two bit strings, character by character. It computes no crypto value. `binaryOf` and `bitsChanged` are pure functions in `walk.ts`. Marked bits also change weight or underline, so colour is never the only sign.

With Show keys OFF, the closed views show no hex, so they offer no tip.

### 2.2g Typing your own text (W1b, W2)

Steve's ruling: "We should allow a user to enter a string. For some lessons, we can truncate it to 16 characters (I would allow a string to be any length and visually show with a squiggle or background color which parts are not included (if the user types more than 16 charaters). Entering less than 16 characters just requires some padding."

| What is typed | One-block view (chapter 1) | Multi-block view (section 2.4c) |
|---|---|---|
| Any length, up to the Host's limit | Uses the first 16 bytes | Uses the whole string |
| Past the 16th byte | Stays visible in the box, with a squiggle and a background colour, and the words "Not included" | Not applicable |
| Under 16 bytes | Padding fills the block, and the grid marks those cells as padding | The last block gets padding, as lesson 1 pads |
| 16 bytes, no more | No padding in this view | A full extra block of padding, as lesson 1 pads |
| Empty | The box goes back to `Pump four is ok.` | The same |
| Past the Host's limit | The same marking, from byte 65,537 | The same marking, from byte 65,537 |

**Which views have the box.** Chapter 1's block walk (W1b) and the longer text view (W2). Chapter 2's mode tabs do not, because they show messages the run sent.

**The box itself sets no limit.** A learner can paste any length. The app measures it and marks what no view reads. Only the included part goes to the Host, up to 65,536 bytes. Chapter 1 sends that same text, and the engine picks the 16 bytes, so the rule for the cut lives in one place.

The default stays `Pump four is ok.`, so the walk that Steve first steps through does not change. A typed block reads "Your text. It did not go on the wire", in place of the teaching-example label.

**The unit is bytes, as UTF-8.** AES takes 16 bytes, and a character can take 1 to 4. The screen says: "A block holds 16 bytes. Some characters take more than one byte."

**A character that crosses byte 16 is cut there, at the byte.** The block takes the bytes up to 16, and the character's other bytes count as not included. The box marks the whole character with a split mark, and the panel says: "This character crosses the 16-byte edge. {n} of its bytes are in the block." When decryption comes back to the 16 bytes, those bytes are not a whole character, so the grid shows their hex, and the readable line shows `·` for them. I chose this over cutting back to a character boundary, because that would add padding that the learner did not ask for, and it would hide that AES works on bytes. **What would change my mind:** a reader finds the split mark more confusing than a shorter block.

**Padding in the one-block view is a teaching fill.** The bare block walk has no mode, so nothing in AES asks for it. It uses the rule lesson 1's ECB and CBC use, from `Lesson01Aes.Pad`: n bytes, each of value n. So `Pump` gets 12 bytes of `0c`. The panel says: "AES needs 16 bytes, so we fill the rest. Each fill byte holds the number of fill bytes. ECB and CBC in this lesson pad the same way." At 16 bytes this view adds nothing, and the panel says: "A mode with this padding adds a whole extra block here. Chapter 2 shows that." So this view keeps the words "teaching fill", because PKCS#7 pads a full block at 16 bytes and this view adds nothing there. The ECB and CBC views may name it: "PKCS#7 padding", off-screen source RFC 5652 section 6.3, which Jared read. `Lesson01Aes.Pad` does this.

**The Host's limit: 65,536 bytes of UTF-8.** That is 4,097 blocks with padding, and a reply of about 700 KiB by estimate, with base and flipped rows about twice that. W2 measures it and records the result in `docs/learnings.md`. The app pages the rows, 64 at a time, from one reply. Past the limit, the app sends text up to the last whole character below the limit, and it marks the rest as not included. The screen says: "This view reads the first 65,536 bytes." The Host still refuses more, with `WALK_TEXT_TOO_LONG`, and it rejects a body over 512 KiB before it reads it. That body limit allows for JSON escapes.

**Steve chose the key. His answer: "Practice".** So the engine does all encryption **under one fixed practice key and one fixed IV,** by a query that adds no trace event. Both come from a label by SHAKE256, as `TrainingKeySource` does, so they are public in the source. Goldens stay unchanged. Typed text enters no trace, session file, or log, and the app prints it as text, never as HTML. The query needs no run, so the box also works beside a loaded replay. Lone surrogates in the text get 400 `WALK_TEXT_INVALID`.

**Why not the run's key, in one line for the reader:** "Your text runs under a practice key, because the course must not lock whatever you type under the key this run uses." The reason: ECB of a typed block of 16 zero bytes under the run's key is GCM's hash key H (`Gcm.cs:51`), which `/ghash` and `/forge` close to protect. An encrypt-anything service on that key would hand it over, and the key can be a learner's own test key.

| View | Show keys OFF | Why |
|---|---|---|
| The text box | Open | It holds only what the learner typed |
| One-block typed walk | **Open** | It shows the practice key and its round keys, and that key is public in the source and protects nothing. Show keys OFF hides the keys a run uses. The panel says so: "This is a practice key, not this run's key. It is public, so it stays on screen with Show keys off" |
| Multi-block view | **Open** | The reply holds the text and cipher blocks under the practice key, and no key of a run |
| `/tables`, `/modes` | Open, as before | No change |

`keySource` names this key `typed-practice`, apart from section 2.7's `practice` key at 192 and 256 bits, which comes from the session seed and closes with Show keys OFF.

**Typing changes the key on screen.** While a typed block is in chapter 1, the key schedule part and the grids use the practice key, and the panel says: "This key differs from the run's." Clearing the box goes back to the run's key, and Show keys OFF closes that walk again. **What would change my mind on open:** a reader takes a key on screen with Show keys OFF as a broken toggle. Then the typed walk closes too, and only the multi-block view stays open.

### 2.2h Spec cards: a standing rule for every screen

Steve's rule: any mention of a named spec on any screen, in any lesson, is a hover card with a short synopsis and a link to a page that explains it. This covers FIPS 197, SP 800-38A, SP 800-38D, RFC 8446, X9.24, and the rest. It binds the new look too, so `docs/ux-design.md` carries it.

| Behaviour | Rule |
|---|---|
| Opens on | Hover, keyboard focus, and tap |
| Stays open | While the pointer is on the card, so the link can be clicked |
| Closes on | Esc, or leaving it. A tap elsewhere closes it too |
| Link | Names one page. A click opens it in the system browser, and the course never loads it inside the app |

**One table, as data: `app/src/specs.json`.** Each row holds `id`, `name`, `aliases`, `title`, `synopsis`, `url`, and `linkText`. A top-level `hosts` list names the hosts a link may use. Jared checks each synopsis and each link. A15 reads the synopses for reading grade, and A15a reads them for accuracy.

**How it reaches tour text and lesson JSON: the app finds spec names when it renders, so the tour files do not change.**

| Choice | Result |
|---|---|
| **Find names at render (chosen).** `specParts(text)` in `tour.ts` splits text on a pattern built from the table's names and aliases, longest first, so `X9.24-3` wins over `X9.24`, as `splitText` splits `{{term:id}}` today | The 12 tour files stay as they are, so no A15a reader re-stamp. A new mention gets its card with no edit. Text the engine sends is covered too |
| A `{{spec:id}}` mark in the tours | Each mention is an edit, the text hash changes, and the reader re-stamps each lesson. An unmarked mention gets no card, and Host messages have no marks |

| Where a spec name can reach the screen | How it gets its card |
|---|---|
| Tour text, in `lesson-NN.json` `text`. Today: `X9.24-3` in lesson 6, `RFC 8996` and `RFC 7465` in lesson 7, `RFC 9449` in lesson 10 | `TermText.vue` runs `specParts` on the text between term marks |
| `glossary.json`, `walk-gloss.json`, `wizard-copy.json` | The same component |
| Text the engine or Host sends: `error.message`, `check.detail`, a refusal's detail. For example, the TLS 1.3 refusals name RFC 8446 sections | Each panel that prints it uses `TextWithSpecs.vue` |
| Words written in a `.vue` template | They use `<SpecCard id="fips197" />` directly |
| A claim's `source` in lesson JSON | Off screen, so no card. A source can name a spec with no row |

**`specs.json` holds a row for each name on screen,** including `PKCS#7` from section 2.4c and `PKCS12` from `wizard-copy.json`. DUKPT rows use the names as they appear on screen. Today that is `X9.24-3` only.

**Section numbers stay as text.** "RFC 8446 section 4.2" gets a card on "RFC 8446", and the words "section 4.2" stay beside it. Names that are not specs, such as `TLS 1.3`, get no card unless the table lists them.

**Links need new code in Electron.** `app/electron/main.cjs` has no window-open handler today. It gains `setWindowOpenHandler`, which always denies a new window, and it denies `will-navigate`, because a plain link does not reach that handler. It calls `shell.openExternal` only when the URL is `https:` and its host is in `hosts`. On Windows, `file://` with a listed host is a network path, so a host check alone is not enough. The renderer asks through `preload.cjs`. The app fetches nothing from these hosts, and a card works offline except for its link. Under `vite preview`, the link is a normal `target="_blank" rel="noopener"`.

**Show keys:** a card holds no key, so it stays open in every state.

### 2.2i The MixColumns matrix view (W1b)

Steve's words: "I want to show where the elements come from and how the multiplication result is built."

The step shows: fixed matrix × state before = state after. It walks one output byte at a time, in this order:

| Moment | On screen | Value from the reply |
|---|---|---|
| 1. Pick | A column, by its control or a tap on its byte | The step's `terms`, in `r + 4c` order |
| 2. The row and column | The matrix row lights. The state column flies up above the matrix, and a box links each pair | Each part's `factor` and `input`. The matrix itself comes from the factors, so the app stores no matrix |
| 3. Each multiply | A caption and bit rows, one part at a time | `doublings`, `picks`, `sums`, `result` |
| 4. The running XOR | A line builds, term by term | `running` |
| 5. The byte lands | It lands in its result cell | `result`, which equals the state after |

**Controls in this view:** pick a column, Back, Next, Play this column, and Fill all. This is the one Play button, in this view scoped to the column, so it still stops at a natural end. Fill all shows the engine's state after.

**InvMixColumns works the same way,** with factors 14, 11, 13, 9. Each of those needs 3 doublings. The panel shows each doubling, then the picks that make up the factor: 14 is 8 + 4 + 2, so `14 x 04` picks `08 10 20`, and its sums run `08 18 38`.

**The multiply as bit rows.** For a factor other than 1:

| Row | No overflow | Overflow |
|---|---|---|
| The byte | `from` | `from` |
| Shift left | `shifted`, which fits | `shifted`, with bit 8 shown |
| The top bit breaks away | | Bit 8 flies off the screen |
| XOR 1b | | The rest of `11b` |
| The doubled value | `to` | `to` |
| 3 x only: XOR the byte, and the answer | `input`, `result` | `input`, `result` |

**Words on screen:**

1. The caption: "2 × d4 = b3: shift left to get 1a8, too big, so XOR 11b."
2. On overflow: "The top bit does not fit in a byte, so it breaks away. Reducing by 11b removes that bit and XORs 1b into the rest."

Dropping the bit alone gives the wrong byte, so the XOR 1b row always shows. The "1b" and "11b" are the field's reduction value. They come from section 2.2c's definition, so the panel prints them as words and computes nothing with them.

**New reply fields: yes, two kinds.**

| Field | Why |
|---|---|
| `running`, on each mixed byte | The XOR after each term. The app runs no math, so the engine sends it. The last value equals `result` |
| `doublings` holds `from`, `shifted`, `reduced`, `to` in place of one byte each. `picks` and `sums` join each part | Bit rows need the 9-bit `shifted` value, and the inverse factors need the picks and their running sum. `to` equals `shifted`, XOR `11b` when it overflows |

Pause and Resume follow section 2.2a in this view too. **Back during play stops Play, ends every flying byte and bit, and lands on the previous whole moment,** with no box, flyer, or lit row left behind. Next during a motion jumps to that motion's end. With reduced motion, each moment lands at once. A Show keys flip stops it all, as section 3.5 sets out.

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
| No byte maps to itself, and no byte maps to its opposite: 0 of 256 each | Sheet 5.8, and the lead's script |

**Real data.** The tables come from `AesKey`'s own `Sbox` and `InverseSbox`, through `GET /api/walk/aes/tables`. The app stores no copy in source. The spike checked that a table lookup equals the walk's swap on 320 of 320 cells, over SubBytes and InvSubBytes.

**Show keys OFF.** The tables are public, so the table and a free lookup stay open: the learner can type any byte. The block grid and its real states stay closed (section 3.5).

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

`Gcm.cs` never calls `DecryptBlock` (sheet 5.2). The panel walks the 4 counters, and it names the other 2 calls. The GCM panel says: "The G in GCM means Galois. GHASH makes the tag in a much larger Galois field, GF(2^128)." The panel shows the `GCM tag` result from the run's own `check.result` event. Section 2.4a walks GHASH.

**Live checks from the run.**

| Row field | Means |
|---|---|
| `status: match` | The block the receiver got equals the block the sender locked |
| `status: differs` | A tamper plan changed this block on the wire. Only a flip can cause this, because a walk bug throws instead (below) |

**Two sets of wire bytes, so a bug and a tamper cannot share a word.** `wire.sent` holds the bytes after the tamper (`EnginePump.cs:342`). The sender's bytes come from the same event with the session's plan undone: a byte flip is its own inverse, so calling `TamperPlan.Apply` on the received bytes gives them back. With no plan, the two sets are equal.

- **The lock column always uses the sender's bytes.** Every block must equal the walk's lock result, on every session, or the query throws `AES_WALK_DIVERGED`. The check covers all blocks of the message, including rows the reply caps.
- **The unlock column always uses the received bytes**, as the receiver did.

In lesson 1, a free flip on a non-wire event changes nothing. `Interpreter.ApplySend` skips the plain tamper point when the effect already holds its wire bytes, and `Lesson01Aes` sends that way. So the fork matches its parent, and every row reads `match`. No lesson 1 attack row uses `Replacement`. A plan that holds one gets 409 `WALK_MESSAGE_REPLACED`.

**Every place a flip can land.** The reply's `damage` field names the frame field from the message's layout.

| Flip lands in | Rows | Unlock | The learner sees |
|---|---|---|---|
| CBC or ECB cipher block | That row `differs` | Runs on the received bytes | CBC: that block turns to junk, the next block has the same bit flipped, then it recovers. The spike's `L1-flip-cbc` run changed 16, 1, 0, 0, 0 bytes per block. ECB: that block turns to junk. Neither raises an error |
| CBC IV | All `match`, `damage: iv` | Runs on the received IV | Block 1 has the same bit flipped. No junk block and no error |
| GCM cipher block | That row `differs`, `damage: cipher` | None. The tag failed, and the engine returns no bytes | The failed tag |
| GCM nonce | All `match`, `damage: nonce` | None | The failed tag. The lock column still shows the nonce the sender used |
| GCM tag | All `match`, `damage: tag` | None | The cipher blocks arrived intact, and the tag failed |
| Frame header, type or length | All `match`, `damage: type` or `length` | None | The receiver read this frame as something else. Most flips end in a named failure, and the panel shows it from the run's own events. A type flip can land on another message the state allows, and then no check fires. On `TextCbc`, xor 10 makes it `TextEcb`, and the run completes with no error |

**The chapter ends with "Mistakes people make".** Each row points at an attack the lesson already runs, so this adds no route and no engine code. Steve's links show these habits in real writing. The on-screen words name the habit and never a person or a page, and Jared checks them first.

| Mistake | What the learner runs | What the learner sees |
|---|---|---|
| ECB, the default in some tools | `L1-use-ecb` | Equal blocks give equal cipher blocks |
| CBC with no tag. A strong key does not fix this | `L1-flip-cbc` | In this lab, a flipped bit passes with no error. A library that checks padding can raise an error on a flip near the end, and it still passes a flip in the earlier blocks |
| A repeated GCM nonce | `L1-reuse-nonce`, then `L1-forge-last-block` | Two messages share a key stream, and only the lab's detector calls it out. The forgery demo shows what that costs (section 2.4b) |

Off-screen sources for these words. MySQL 8.4 Reference Manual, `block_encryption_mode`: default value `aes-128-ecb`. .NET 10.0.14 `Aes.Create()`, run by Jared: CBC and PKCS7 by default, and a flip in an earlier block raised no error on 384 of 384, while the second-last block raised a padding error on 128 of 128 for a 64-byte text and on 56 of 128 for a 41-byte text, and the last byte of the 64-byte text raised one on all 8 bits. MySQL stays off the screen.

**Out of scope, named on the tab.** The modes page also lists CFB, OFB, and CTR, and it names XTS. CFB, OFB, and XTS are not in this course (grep of `src/NetSec.Core`: 0 files). CTR alone runs in lesson 8's SSH suite, and the panel points there. Lesson 1 runs counter mode only inside GCM.

### 2.4a GHASH: how the GCM tag is made (W1c)

Steve moved this into the modes chapter. Facts come from SP 800-38D and Jared's sheet section 5.18. It opens from the GCM tab, and it uses the run's `TextGcm1`.

| Step | On screen | Value from the engine |
|---|---|---|
| 1. H | AES locks a block of 16 zero bytes. The result is the hash key H | `Hash` |
| 2. Each cipher block | Y starts at zero. XOR the cipher block into Y, then multiply Y by H in GF(2^128) | One row per block: `Before`, `Block`, `AfterXor`, `AfterMultiply` |
| 3. Lengths | XOR a last block that holds both lengths in bits, then multiply by H | The same row shape, with `IsLengths` |
| 4. Mask | AES locks the nonce with count 1. The result is the mask | `CounterBlock`, `Mask` |
| 5. Tag | Y XOR the mask | `Tag`, which must equal the frame's tag |

**Words the panel must get right, from sheet 5.18:**

1. "The nonce is not in GHASH. A changed nonce still fails, because the mask changes."
2. "GCM needs no padding, because XOR uses only the key stream bytes it needs." GHASH zero-fills a short block for its own use, and that changes no sent byte.
3. "AAD is empty in this lesson, so GHASH starts at the cipher blocks."
4. The tag check comes first in this engine, and no text comes out on a failure.

The multiply stays one step on screen. Its 128 shifts teach nothing beyond section 2.2c, so the panel shows only input and result.

The bit order inside GF(2^128) is reversed from section 2.2c's: the field's 1 is `80 00 ... 00`. The panel does not teach this. A clause pins it through the values.

### 2.4b The forgery demo: what a repeated nonce gives away (W1c)

Steve's ruling: show what the repeated-nonce mistake costs. An eavesdropper with two frames and no key forges a message that the real check accepts.

**What runs.** A new attack row, `L1-forge-last-block`. The client sends `TextGcm2` under the first nonce, with its last block changed to `Pump four failed`, and with the same length. `L1-reuse-nonce` cannot do this: it sends the same text twice, so the two frames differ nowhere.

**The maths, on 4 blocks with empty AAD** (`+` is XOR, and multiply is in GF(2^128)):

| Step | Formula |
|---|---|
| 1. The tag | `T = C1 H^5 + C2 H^4 + C3 H^3 + C4 H^2 + L H + M`, where `M` is the mask |
| 2. Two frames, one nonce, only C4 differs | `T + T' = (C4 + C4') H^2`. M, L, and the other terms cancel |
| 3. Solve | `H^2 = (T + T') / (C4 + C4')`, then a square root. Squaring is one-to-one here, so there is one answer |
| 4. The mask | `M = T + GHASH(H, C)` |
| 5. Forge | `C4'' = P'' + (C4 + P4)`, which needs the known text only. The new tag is `GHASH(H, C1 C2 C3 C4'') + M`, under the same nonce |

**On screen, in order:** the two frames from the wire, the blocks that differ, H with the line "Recovered with no key", the forged last block `Pump four closed`, and the real check's answer.

**Three truths the panel states:**

1. The lab's detector stops this run at the repeat. So the forged message goes to `Gcm.TryOpen` in the query, not through the lab. "The detector is a lab feature. Real GCM has no such alarm" (`L1-C04`).
2. This demo covers two messages that differ only in the last block. The general case needs root finding, and SP 800-38D Appendix A says only that an attacker can "likely" find H.
3. The fault is the repeated nonce. AES and GCM are fine when each nonce is used once.

**Closed with Show keys OFF, on Jared's recommendation, because H is key material.** Steve approved the demo and can overrule this. The recovery needs no key, and the forged tag rests on H.

**Control run and goldens stay unchanged.** The row reads a new lab option, and with the option absent, `Lesson01Aes` takes the same path and draws the same random bytes. No result enters a trace or a session file.

**A checked test case, off screen.** Key `000102...0f`, nonce `a0a1a2a3a4a5a6a7a8a9aaab`, text `Pump four is ok.` 4 times, then the last block `Pump four failed`, then forged `Pump four closed`. T1, C4, T2, and C4' came from the real `Gcm.Seal`. H and the forged values came from the spike, from the frames alone, and the real `Gcm.TryOpen` accepted the result. M is from Jared's Python, and the forged tag depends on it.

| Value | Bytes |
|---|---|
| T1 | `ced9be742e604bd3c021c4aca8730192` |
| C4 | `ec21213913e7f998f016e7b9c50a6f53` |
| T2 | `04cd111a6c8a0ba9a02a0e083f48a21b` |
| C4' | `ec21213913e7f998f016e8ab8c096119` |
| H | `c6a13b37878f5b826f4f8162a1c8d879` |
| M | `fcee691d22c779b3a1a6d8a277507065` |
| Forged last block | `ec21213913e7f998f016eda68a166119` |
| Forged tag | `4207b367ff74886a6fec40259d3939e0` |

### 2.4d The GCM stream view (W1c)

Steve's item. It opens from the GCM tab, on the run's `TextGcm1`. It shows that AES locks counters and never sees the text. The text then XORs with the key stream, one byte at a time. The build waits until W1a is done.

| Part | On screen | Value from the engine |
|---|---|---|
| A block | A counter, then 3 rows: Text, Key stream, and Sent | `/modes` row: `count`, `lockIn`, `data`, `lockOut`, `cipher` |
| One byte | "p (70) XOR a3 = d3", with the bits below it, and the sent byte lands | Byte j of `data`, `lockOut`, and `cipher`. The app prints them and computes no XOR |
| The end | "64 bytes in, 64 bytes out. No padding." | The byte counts of `data` and `cipher` |
| The tag | H, the mask, and the GHASH table | `/ghash`, as section 2.4a sets out |
| A flip | The tags differ, and the words in the list below show | `/ghash` `flip` |

Controls: Play the stream, Pause, Resume, Next, and Show all. Pause and Resume follow section 2.2a. Flip one bit is one button, and pressing it again puts the bit back.

**The flip's words:** "The tags differ, so the receiver rejects the message and returns no text. Without the tag, it would read:" and then the text. With no flip: "The tags match, so the receiver accepts the text."

**The flip runs in the walk and changes nothing in the run.** The panel says so. The trace gets no event, and the lesson's own attack stays the way to flip a byte on the wire. The engine returns no text on a failed tag, so "would read" comes from the walk and never from `Gcm`'s open path.

**What the routes already hold, and what is missing:**

| Need | Status |
|---|---|
| Counter block, key stream, text, sent bytes | Held: `lockIn`, `lockOut`, `data`, `cipher`. GCM's `data` has no padding, so its length gives the bytes used |
| H, mask, table, tag | Held: `/ghash` `hash`, `mask`, `rows`, `tag` |
| The counter's number | **New:** `count` on a GCM row. The app would otherwise read it out of `lockIn` |
| The flip | **New:** `flip` on `/ghash`: `byte`, `bit`, `cipher`, `computedTag`, `textWithoutTag`. The engine picks one bit and works these out |

Neither field touches W1a, because `/modes` and `/ghash` arrive in W1c.

**Show keys OFF.** The stream rows stay open, as `/modes` does today, because each key stream byte equals text XOR cipher. The tag section closes, because `/ghash` holds H. `flip` must close with it even with H removed: `tag` XOR `computedTag` is the changed block times a power of H, so a client that held both could recover H.

**Unused key stream bytes need care.** A short last block leaves key stream bytes no XOR used. Text XOR cipher cannot give those bytes, so they are new AES output, and the reason `/modes` stays open does not cover them. Two rules follow:

1. `TextGcm1` is 64 bytes, so it fills its 4 blocks and has no unused bytes. **So the strike-through never shows on the run's own message.**
2. The struck-through bytes and their words arrive with typed text, under the practice key, in a separate slice after W1c: "No padding. The last block used 9 key stream bytes and dropped the other 7." On a run's key, `lockOut` holds only the bytes the text used.

**Two things in the mock that the build changes:**

1. It says "Made-up values, for the walk only". This view uses the run's real message, so those words go.
2. It lists other data the tag protects. AAD is empty in this lesson, and section 2.4a's words already say so, so that line goes.

### 2.4c A longer text, and the picture (W2)

Steve's ask, after CrypTool 2's "Block Modes" template: a view with many blocks, where the mode's effect shows. We take the idea and no code or image.

**The view:**

1. The text, cut into blocks, with the last block marked "+ padding".
2. ECB and CBC cipher blocks side by side. Repeats are shaded, with a count.
3. A control flips one bit of the text in a chosen block. The view counts changed cipher blocks, and changed bits per block.
4. The picture beside it: clear, ECB, and CBC, from the run.

**The learner types the text, by Steve's ruling (section 2.2g).** The view uses the whole string. The box starts with a built-in text that holds repeats on block boundaries. The panel says: "ECB shows a repeat only when 16 equal bytes fill a whole block in both places. A shorter repeat, or one shifted by a few bytes, can stay hidden."


| Question | Answer |
|---|---|
| Which key? | The practice key, as section 2.2g sets out. The panel says: "This key differs from the run's" |
| Which IV? | One fixed IV, so a flip compares like with like, and a clause can recompute every value with the BCL. The panel says: "This view uses one fixed IV so that a flip compares fairly. A real system uses a new unpredictable IV for each message. With one fixed IV, two texts with the same first block give the same first cipher block." The learner can see that by typing twice |
| The flip | One query returns both the base rows and the flipped rows. The flip must land on a text byte, because a padding bit is not a text bit, and `WALK_BAD_ARGUMENT` refuses the rest. So at 16, 32, ... bytes, the last block offers no flip. A flipped bit can make invalid UTF-8, so the view shows flipped data as hex |
| Show keys OFF | **Open**, as section 2.2g sets out |
| Session needed? | No. The route takes the text and reads no run |
| Trace? | The route writes no event. The text enters no trace, session file, or log |
| The picture | No route. `PicturePanel.vue` already reads the run's `PictureEcb` and `PictureCbc`. It gains a side-by-side layout. The counts come from the run's `measure.result` events. The eavesdropper view still hides the clear picture |

**Words on screen, from Jared (sheet 5.19):**

1. "Both views use the same AES on each block. The mode is the difference: ECB locks each block alone, so equal text blocks give equal cipher blocks. CBC mixes in the block before, so these repeats do not show."
2. With engine values: "One text bit changed. ECB: {n} block changed. CBC: {n} blocks changed, this block and all after it. Bits changed in each block: {list} of 128."
3. Only if the panel names the words: "Shannon named two goals in 1949: confusion and diffusion. Teachers often credit the S-box with the first, and ShiftRows and MixColumns with the second. Both are at work inside one block here, in both views."

Jared's run on the claim, off screen: 400 random keys, IVs, and flips on the lesson text. ECB changed the flipped block only, 400 of 400. CBC changed that block and all later ones, 400 of 400. Bits changed per changed block: 1,402 blocks, mean 63.8 of 128, range 45 to 84.

The flip here is a **text** bit. Section 2.4's damage pattern is a **cipher** bit, and it differs. Each view carries its own label.

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
| "XORs the round key" | "Adds the round key", with no XOR named |
| "Decryption starts with AddRoundKey, using the last round key" | "The inverse round key" |
| "The CBC IV must be unpredictable. The GCM nonce must be unique" | "Unique IV" for CBC, or one IV rule for all modes |
| "One block turns to junk, and the next has the same bit flipped. Then it recovers" | "A corrupted block affects subsequent blocks" |
| "This engine checks the tag first. No text comes out on a failure" | "GCM must check the tag first", as a rule of the standard |
| "Shows patterns" for ECB | "Vulnerable to cryptanalysis" for ECB |
| "The same AES runs inside both. The mode is the difference" | "ECB has no confusion" or "ECB lacks diffusion". AES supplies both inside a block, and a mode shows or hides repeats across blocks |
| "CBC carries a change forward" | "CBC adds diffusion" |
| Measured bit counts from the engine | A fixed half, or a fixed 64. Diffusion defined as "one bit changes half the output" |
| "This block and all after it". A flip in the last block changes only that block | "A change spreads to all blocks" in CBC |
| "CBC hides these repeats. It still needs an unpredictable IV, and it has no tag" | "CBC is safe", or "CBC fixes ECB" |

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
| Which key size (chapter 1) | One selector |
| Which mode (chapter 2) | Three tabs |
| Typed text | One box. Past the used part, it marks the text as not included |
| Longer text (W2) | A block picker and a Flip button. The modes sit side by side, so there is no mode control |
| Move through steps | Back, Next, and round chips to jump |
| Watch steps move | One button: Play, Pause, Resume, by state (section 2.2a). Play stops at the end of the round, and pressing it again starts the next round. Pause freezes in mid-motion. Steve can overrule the stop after he steps through W1b |
| How fast | One speed control: slow, normal, fast |
| See one word's build | Tap a built word in the table |
| See one byte's lookup | Click a cell |
| See a value in binary | Hover or focus. No control |
| Open an AES box (chapter 2) | Click the box |

Cut: a separate "Play this round" button, because Play already stops there, a separate encrypt/decrypt switch (decrypt follows encrypt in one step list), and a stand-alone S-box page.

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

**Other projects, read as leads only.** `kokke/tiny-AES-c`, `SergeyBel/AES`, and `abdouskamel/aes-csharp` split SubBytes and ShiftRows in their one real path, in the same order as FIPS 197 and this design. None of their cipher calls takes an observer or returns round states, so none offers a better shape for the walk. Nothing here copies their code.

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
    public readonly AesColumnByte[] Terms;    // MixColumns and InvMixColumns only. Else null
  }
  public sealed class AesBlockWalk { public readonly int Rounds; public readonly byte[] Input, Output; public readonly AesStep[] Steps; }
  public sealed class GhashRow {              // One XOR and multiply. IsLengths marks the last row
    public readonly byte[] Before, Block, AfterXor, AfterMultiply;
    public readonly bool IsLengths;
  }
  public sealed class GhashFlip { public readonly int Byte, Bit; public readonly byte[] Cipher, ComputedTag, TextWithoutTag; }   // One bit flipped in the walk. The run does not change
  public sealed class GhashWalk { public readonly byte[] Hash, CounterBlock, Mask, Tag; public readonly GhashRow[] Rows; public readonly GhashFlip Flip; }
  public sealed class AesKeyWord {            // One row of the FIPS 197 appendix A tables. An unused cell is null
    public readonly int Index;
    public readonly int Divisor, Quotient, Remainder;   // Index / Nk, the test FIPS 197 section 5.2 applies to this word
    public readonly byte[] Previous, Rotated, Substituted, Rcon, AfterRcon, KeyBack, Word;
  }
  public sealed class AesDoubling {          // One field multiply by 2
    public readonly byte From; public readonly int Shifted;   // Shifted is 9 bits, before the reduction
    public readonly bool Reduced; public readonly byte To;
  }
  public sealed class AesTerm {               // One factor x input term of a mixed byte
    public readonly int Factor;               // 2, 3, 1 or 14, 11, 13, 9
    public readonly byte Input;
    public readonly AesDoubling[] Doublings;  // As far as the factor needs. The inverse factors need 3
    public readonly byte[] Picks, Sums;       // The input and doubled values that make up the factor, low bit first, and their running XOR
    public readonly bool Reduced;             // Any doubling needed the reduction by 11b
    public readonly byte Result;
  }
  public sealed class AesColumnByte { public readonly AesTerm[] Terms; public readonly byte[] Running; public readonly byte Result; }   // Running is the XOR after each term. Its last value is Result
  public sealed partial class AesKey {
    public AesBlockWalk WalkEncrypt(byte[] block);   // Throws AES_WALK_DIVERGED if it differs from EncryptBlock
    public AesBlockWalk WalkDecrypt(byte[] block);   // Throws AES_WALK_DIVERGED if it differs from DecryptBlock
    public AesKeyWord[] WalkKeyExpansion();          // Nb * (Nr + 1) rows
    public static byte[] SubstitutionTable();        // A copy of Sbox, 256 bytes
    public static byte[] InverseSubstitutionTable(); // A copy of InverseSbox, 256 bytes
    public static int[] ShiftMap(bool inverse);      // A copy of ShiftRowsMap or InverseShiftRowsMap
    public static int[] DependsOn(AesStepKind kind, int cell);   // W2. The earlier cells this cell depends on (section 2.2e)
    public static byte[] RoundConstants(int count);  // Each value is the one before it, doubled in the field
    public static AesDoubling[] RoundConstantSteps(int count);   // count - 1 doublings, one between each pair of values
    public static AesColumnByte[] MixTerms(byte[] before, bool inverse);   // One entry per state byte, in r + 4c order
  }
  public static class Gcm {                   // Added to Gcm.cs
    public static byte[] CounterBlock(byte[] nonce, int blockIndex);   // nonce, then 32-bit blockIndex + 2
    public static GhashWalk WalkTag(AesKey k, byte[] nonce, byte[] aad, byte[] cipher);   // Throws AES_WALK_DIVERGED if Tag differs from ComputeTag
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
    public int Count;                         // GCM: the counter's number, from 2. Else 0
    public byte[] LockIn, LockOut;            // Into and out of forward AES. On a run's key, a short GCM block holds only the bytes the text used
    public byte[] Cipher, Received; public AesWireStatus Status;   // Cipher: what the sender locked
    public AesPass UnlockPass;                // Inverse for ECB and CBC, Forward for GCM
    public byte[] UnlockIn, UnlockOut, Result;   // Null when the receiver gave no bytes
  }
  public enum AesTagState { NotAGcmMessage, NotRun, Passed, Failed }
  public sealed class AesFeedWalk {
    public AesFeedMode Mode; public string Message;
    public byte[] Starter, ReceivedStarter;   // CBC IV or GCM nonce, as sent and as received. Else null
    public string Damage;                     // The frame field a flip hit: iv, nonce, cipher, tag, type, length. Else null
    public AesTagState Tag;
    public int TotalBlocks, ForwardCalls, InverseCalls; public AesFeedRow[] Rows;
  }
  public sealed class AesLongTextRow {       // One padded block, ECB and CBC
    public int Block; public byte[] Data, Ecb, Cbc;
    public bool EcbRepeat, CbcRepeat;
    public int EcbBitsChanged, CbcBitsChanged;   // Zero when no flip was asked
  }
  public sealed class AesLongTextView {     // A repeat count is blocks minus distinct blocks, as Lesson01Aes.MeasureBlocks counts
    public AesLongTextRow[] Rows, FlippedRows;   // FlippedRows is null when no flip was asked
    public int EcbRepeats, CbcRepeats, EcbBlocksChanged, CbcBlocksChanged;
  }
  public static class AesLongText {           // Pure. Uses the real Modes.EcbEncrypt, Modes.CbcEncrypt and Lesson01Aes.Pad
    public const int MaxBytes = 65536;
    public static AesLongTextView Build(byte[] key, byte[] iv, byte[] text, int flipBlock, int flipBit);   // flipBlock -1 means no flip. flipBit is 0 to 127, and it must land on a text byte
  }
  public static class AesPractice {           // Public by design. Both come from a label by SHAKE256
    public static byte[] Key(int keyBits);    // 16, 24 or 32 bytes, each from its own label. A typed block follows the key size selector from W1c
    public static byte[] Iv();                // 16 bytes
  }
  public sealed class AesTypedBlock {         // Chapter 1, from one typed string
    public byte[] Block;                      // Always 16 bytes
    public int UsedBytes, PaddingBytes, NotIncludedBytes;
    public int SplitCharacterBytesIn;         // Bytes of the character that crosses byte 16 that are in the block. Zero when none does
  }
  public static class AesTypedBlocks {        // Pure. Throws WALK_TEXT_EMPTY, WALK_TEXT_TOO_LONG, WALK_TEXT_INVALID
    public static AesTypedBlock Cut(string text);
  }
  public sealed class GcmForgery {            // Every value comes from the two frames and the known text
    public byte[] Hash, Mask, ForgedBlock, ForgedTag, ForgedBody;
  }
  public static class GcmForgeries {          // Pure. No AesKey parameter, so it cannot read a key. Throws NetSecException with the codes below
    public static GcmForgery Recover(byte[] nonce1, byte[] sealed1, byte[] nonce2, byte[] sealed2, byte[] knownLast, byte[] forgedLast);
  }
  public static class AesWalks {              // Pure. Same input, same output. No session, no socket
    public static AesBlockPair Block(byte[] key, byte[] forwardInput, byte[] inverseInputOrNull);
    // senderFrame and receivedFrame are whole frames. They are equal when no plan touched this message.
    // Throws AES_WALK_DIVERGED if any lock result differs from senderFrame.
    public static AesFeedWalk Feed(byte[] key, AesFeedMode mode, string message, byte[] plain, byte[] senderFrame, byte[] receivedFrame, AesTagState tag, int maxRows);
  }
}
```

`WalkEncrypt` and `WalkDecrypt` fill `Terms` from `MixTerms`, on the state before the step, and throw `AES_WALK_DIVERGED` if any `Result` differs from the state after it. The doublings use the existing `Xtime`, so the real path's `Times` tables stay untouched.

`Gf128` gains `Inverse` and `SquareRoot`, built from repeated `Multiply`. The field's 1 is `80 00 ... 00` in GCM's bit order, which is the trap in the power loop. `Gcm.WalkTag` runs beside `ComputeTag`, and the real path does not change. `Lesson01Aes` gains `OptionForgeLastBlock`, and `AttackCatalog` gains the row.

`Gcm.CounterBlock` is new and pure. `CounterCrypt` stays as it is. The lock guard catches a drift between the two. `Lesson01Aes.Pad` changes from private to internal, so the feed uses the lesson's own padding. Its bytes and the lab's trace stay as they are. `ErrorCodes` gains `AesWalkDiverged`, `WalkNotBuilt`, `WalkWaitingForWire`, `WalkMessageNotSent`, `WalkMessageReplaced`, `WalkKeySizeNotInRun`, `WalkBadArgument`, `WalkTextEmpty`, `WalkTextTooLong`, `WalkTextInvalid`, `WalkForgeSameText`, `WalkForgeNonceDiffers`, and `WalkForgeTooManyBlocks`.

**`AesWalks.Feed` is a third copy of the mode logic,** after `Modes.cs` and `Gcm.cs`. The lock guard is its run-time pin. A row cannot read `differs` for a Feed bug, because a Feed bug fails the guard first.

Language limits, checked by the spike: no optional parameters, no records, no expression bodies, no target-typed `new`. Types use only `byte[]`, `Buffer`, and `List<T>`.

### 3.4 Host routes and call path

`src/NetSec.Host/AesWalkRoutes.cs`, C# 14, net10. It joins `Program.cs` beside `SecurityRoutes.Map`.

```
GET /api/walk/aes/tables
GET /api/sessions/{id}/walk/aes/block?source=text&keyBits=128|192|256
GET /api/sessions/{id}/walk/aes/block?source=ecb|cbc|gcm&block=0..rows-1
GET /api/sessions/{id}/walk/aes/modes?mode=ecb|cbc|gcm
GET /api/sessions/{id}/walk/aes/ghash
GET /api/sessions/{id}/walk/aes/forge
POST /api/walk/aes/typed-block   { "text": "..." }
POST /api/walk/aes/long-text     { "text": "...", "flipBlock": 1, "flipBit": 0 }
```

`/typed-block` arrives in W1b, and `/long-text` in W2. Each takes the text, so each departs from the rule that a walk route takes no bytes. That rule keeps canned keys and blocks out of the real walk. Here the text is the learner's own, and neither route accepts a key or reads a run's key. `/typed-block` replies as `/block?source=text` does, with `keySource: "typed-practice"`, and with `used`, `padding`, `notIncluded`, and `splitBytesIn` beside it. `/long-text` replies with rows and counts.

`/ghash` and `/forge` arrive in W1c. `/forge` gives a forgery only on a session that ran `L1-forge-last-block`, and any other session gets a named refusal below. The route reads the two frames from `wire.sent`, calls `GcmForgeries.Recover`, and then, as a guard, reads the run's key: the recovered H must equal AES of the zero block, or `AES_WALK_DIVERGED`. It passes the forged body to the real `Gcm.TryOpen` and returns its answer and text.

`source=text` is chapter 1, on block 1 of the text. The other sources open a box in chapter 2. `rows` is the row count that mode's `/modes` reply gives: 5 for `TextCbc` and `TextEcb` with the padding block, 4 for `TextGcm1` and for a capped picture. Only `source=text` takes a `keyBits` other than the run's.

Call path for the two session routes:

1. `/block` reads `security.ShowKeys` first. OFF returns 409 `KEYS_HIDDEN`, as the key log route does. `/modes` skips this step (section 3.5).
2. `sessions.Find(id)`. Null returns 404 `SESSION_NOT_FOUND`.
3. `session.Lesson != 1` returns 409 `WALK_NOT_BUILT`.
4. `AesWalkFacts.Read(session.After(0), session.TamperPlan)` reads the facts. It filters on `StoredEvent.Type`, `Message`, and `StreamId`, and parses only those shown lines:
   - `aes.key`, and the `plain` of each `aes.message.sent`.
   - The `wire` of the client's `wire.sent`, which is the received frame. Calling `TamperPlan.Apply` with the `StreamId` and `StreamSeq` of the client's `aes.message.sent` gives the sender's frame. It must be that event's address and not the `wire.sent` event's own, because a free flip plan is addressed by stream. `EnginePump.cs:342` and `SessionManager.PlanFor` use the same address.
   - The tag result. All three GCM checks have the message `GCM tag`, so the filter also reads `step`: `aes.s.text-gcm-1` belongs to `TextGcm1`. No such event gives `NotRun`.
5. `AesWalks.Block` or `AesWalks.Feed` runs. For a practice key, the Host draws it first.
6. `AesWalkJson.Write` writes the reply, with `Cache-Control: no-store`. English stays out of Core.

`LabSession` gains one read-only field, `TamperPlan`, from `attack?.Plan` at `SessionManager.Start`. It holds no other new state.

`/api/walk/aes/tables` skips steps 1 to 5. The tables are public, so it stays open with Show keys OFF. It still passes `HostGuard`.

Why a session route takes an id and no bytes: a client cannot send a canned key or block, so the real data rule holds at the Host. The toggle also holds at the Host boundary, as in `modes-design.md` section 6.4.

Replies, trimmed. Every error carries `code`, `message`, `retryable`, and `requestId`.

```json
// /api/walk/aes/tables
{ "sbox": "637c777b...", "inverseSbox": "52096ad5...", "shiftRows": [0, 5, 10, 15, "..."], "inverseShiftRows": [0, 13, 10, 7, "..."], "rcon": "01020408102040801b36", "rconSteps": [ { "from": "01", "shifted": "002", "reduced": false, "to": "02" }, "...", { "from": "80", "shifted": "100", "reduced": true, "to": "1b" }, { "from": "1b", "shifted": "036", "reduced": false, "to": "36" } ],
  "sizes": [ { "keyBits": 128, "keyWords": 4, "rounds": 10, "roundKeys": 11, "words": 44, "rconUsed": 10 } ] }

// /block?source=text
{
  "source": "text", "keyBits": 128, "rounds": 10, "keySource": "run",
  "inputHex": "50756d7020666f7572206973206f6b2e",
  "keyWords": [ { "i": 4, "divisor": 4, "quotient": 1, "remainder": 0, "previous": "...", "rotated": "...", "substituted": "...", "rcon": "...", "afterRcon": "...", "keyBack": "...", "word": "..." } ],
  "forward": { "input": "...", "output": "...", "steps": [ { "kind": "AddRoundKey", "round": 0, "state": "...", "roundKey": "..." },
                                                 { "kind": "MixColumns", "round": 1, "state": "...", "terms": [ { "result": "04", "running": ["b3", "69", "34", "04"], "parts": [ { "factor": 2, "input": "d4", "doublings": [ { "from": "d4", "shifted": "1a8", "reduced": true, "to": "b3" } ], "picks": ["b3"], "sums": ["b3"], "reduced": true, "result": "b3" } ] } ] } ] },
  "inverse": { "input": "...", "output": "...", "steps": [] },
  "wire": { "status": "notSent", "message": "TextEcb" }
}

// /modes?mode=gcm
{
  "mode": "gcm", "message": "TextGcm1", "starter": "e4f00aae0569f1494f973a46", "receivedStarter": "e4f00aae0569f1494f973a46",
  "damage": null, "tag": "passed", "totalBlocks": 4, "forwardCalls": 6, "inverseCalls": 0,
  "rows": [ { "block": 0, "data": "...", "chain": null, "lockIn": "...00000002", "lockOut": "...", "cipher": "...",
              "received": "...", "status": "match", "unlockPass": "forward", "unlockIn": "...00000002", "unlockOut": "...", "result": "..." } ]
}
```

| Case | Status and code |
|---|---|
| Show keys OFF, `/block` | 409 `KEYS_HIDDEN` |
| Lesson other than 1, in the pilot | 409 `WALK_NOT_BUILT` |
| `keyBits` other than the run's, with a source other than `text` | 400 `WALK_KEY_SIZE_NOT_IN_RUN` |
| A running session has not sent the message yet | 409 `WALK_WAITING_FOR_WIRE`, `retryable: true` |
| A finished session never sent the message | 409 `WALK_MESSAGE_NOT_SENT` |
| The plan holds a `Replacement` | 409 `WALK_MESSAGE_REPLACED` |
| A bad mode, source, block, or key size, or a flip outside the text | 400 `WALK_BAD_ARGUMENT` |
| Typed text: empty, over 65,536 bytes as UTF-8, or a lone surrogate | 400 `WALK_TEXT_EMPTY`, `WALK_TEXT_TOO_LONG`, `WALK_TEXT_INVALID` |
| Forge: the two frames are the same text, as on `L1-reuse-nonce` | 409 `WALK_FORGE_SAME_TEXT` |
| Forge: the two frames have different nonces, as on a control run | 409 `WALK_FORGE_NONCE_DIFFERS`, with no H shown |
| Forge: anything other than one changed last block | 409 `WALK_FORGE_TOO_MANY_BLOCKS`. This covers more than the last block differing (which needs root finding, and the pilot does not build it), only an earlier block differing (the divisor would be zero), and different lengths (H would come out wrong). No lab row reaches the last two, and `Recover` is public, so it refuses them |
| A guard fired | 500 `AES_WALK_DIVERGED` |

### 3.5 Show keys OFF

**Decision: OFF closes the round states. The public tables and the modes walk stay open.**

| Route | OFF | Why |
|---|---|---|
| `/api/walk/aes/tables` | Open | The S-box tables, shift maps, round constants, size table, and dependency rule are public |
| `/modes` | Open | A row holds no key and no round state. Each field comes from values the trace shows with the toggle OFF: `plain` and `wire`. For example, GCM's key stream equals text XOR cipher |
| `/typed-block`, `/long-text` | Open | They run only on the public practice key, and they read no run's key (section 2.2g) |
| `/ghash` | **Closed**, 409 `KEYS_HIDDEN` | It holds H, and each Y value is built from H |
| `/forge` | **Closed**, 409 `KEYS_HIDDEN` | On Jared's recommendation, because H is key material. Steve approved the demo and can overrule this. The recovery needs no key |
| `/block` | **Closed**, 409 `KEYS_HIDDEN` | It holds the key, the round keys, the word rows, and the MixColumns terms, whose inputs are round states. The first AddRoundKey also gives `state = input xor key`, so input and state give the key. A fingerprint per cell would teach nothing |

So with the toggle OFF, chapter 1's steps close, and chapter 2's rows stay. A chapter 2 AES box stays shut. The block tab shows: "Show keys is off. These steps show the key and the round keys, so they stay closed. Turn Show keys on to walk them. The S-box table, the key size table, the round constants, the field definition, and the modes walk stay open."

`modes-design.md` section 6.5 says each lesson keeps its comparison. That stays true, because the panels of section 6.5 still run.

**The rule for every walk route that reads a key.** This covers W1 and the later lessons 2, 5, 6, 7, and 8, and the section 5 bench.

1. The Host checks the toggle first, before it reads any key.
2. Each reply carries `Cache-Control: no-store`.
3. An error body holds no bytes.
4. A clause lists these routes, so a new one must join the list.

A route may answer with the toggle OFF only if its reply holds no key byte. Lesson 6's fingerprints (section 1.1) meet this rule. The route list names each route's OFF behaviour.

**The limit, from `modes-design.md` section 6.2.** OFF is not a security boundary. It is a setting for a shared screen or a shared trace. The Host still holds the bytes, and each hidden line carries the seed (`SessionManager.cs:79`), and a lab key comes from that seed.

**The flip race.** This is the same class as PRs #140, #141, and #143. A reply can be in flight when the toggle flips, and it does not pass through `ShowKeysFence`. Frames can also drop (`SessionManager.cs:160`, `DropOldest`), and sockets reconnect (`host.ts:91-99`), so the fix cannot rest on the `security.show-keys` frame alone. The fix sits in the app:

1. `walk.ts` holds a generation counter. It rises, the store clears the block walk, and `useWalkTimeline` stops, when `sec.showKeys` goes false by any route (`security.ts:141`, the frame handler, or a reload), and when the socket closes (`store.ts:133`).
2. A reply whose generation is old is dropped. A reply that lands while `sec.showKeys` is false is dropped too.
3. After a reconnect, the app reloads the toggle first, and fetches the walk again only if it is ON.
4. A walk reply never enters a session file, `/events`, or a save.

Echo gets a clause for each of the four, and one that drops the flip frame on purpose.

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
MixColumns and InvMixColumns: terms XOR to the state byte on 1056 of 1056 bytes, all three key sizes, 4224 terms
column d4 bf 5d 30, byte 0: 2xd4=b3 (reduced); 3xbf=da (reduced); 1x5d=5d; 1x30=30; out 04 66 81 e5
inverse, byte 0: 14x04: doublings 08 10 20 -> 38; 11x66: doublings cc 83 1d -> b7; 13x81: doublings 19 32 64 -> d7; 9xe5: doublings d1 b9 69 -> 8c; out d4
Rcon: 01020408102040801b36
AES-128 uses 10 round constants
AES-192 uses 8 round constants
AES-256 uses 7 round constants
real Gcm.Seal: T1 ced9be742e604bd3c021c4aca8730192 C4 ec21213913e7f998f016e7b9c50a6f53
real Gcm.Seal: T2 04cd111a6c8a0ba9a02a0e083f48a21b C4' ec21213913e7f998f016e8ab8c096119
H from two frames, no key: c6a13b37878f5b826f4f8162a1c8d879, equals AES of the zero block: True
forged last block ec21213913e7f998f016eda68a166119, tag 4207b367ff74886a6fec40259d3939e0
real Gcm.TryOpen accepts the forgery: True, text ends: Pump four closed
one tag bit changed: TryOpen says False
tap-a-byte rule: 10240 cases, a byte outside the set changed the cell in 0, a byte inside the set never did in 0
input bytes behind cell 0: after AddRoundKey 0: 1, after round 1 SubBytes: 1, ShiftRows: 1, MixColumns: 4, after round 2 MixColumns: 16
```

The 186 encrypt values and 186 inverse values come from FIPS 197 (2001 edition), appendix C. The comparison is strict, by position. "Jared 5.3" compares with his independent Python AES, which shares no code with the course. The walk file and the `AesKey` copy also compiled against the CF 3.5 references in `E:\dev\tools\netcf35-ref`, with 0 errors and 0 warnings.

Limits of the spike:

1. The walk file ran on the desktop CLR, on the copy of `AesKey`. It compiled for CF and did not run on it.
2. The feed logic in the spike is throwaway code, and `AesWalks` does not exist yet. No route, no app panel, and no Show keys path ran. The sender-frame undo did not run in this spike. Jared ran it in his own scratch folder: `TamperPlan.Apply` gave back the control run's sender frame on 12 of 12 flips (type, length, nonce, cipher, tag, IV), addressed by message and by stream.
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
| `app/src/specs.json`, `components/SpecCard.vue`, `components/TextWithSpecs.vue` | The spec table, the card, and text with its names turned into cards (section 2.2h). `specParts` is pure, in `tour.ts`. `app/electron/main.cjs` and `preload.cjs` gain the link handler |
| `app/src/components/MixMatrixView.vue` | The matrix view of section 2.2i, for MixColumns and InvMixColumns. It prints the engine's terms |
| `app/src/components/KeySchedulePanel.vue` | The key as words, the expanded table of grids, one word's stage rows, the Rcon row |
| `app/src/components/FieldPanel.vue` | The definition lines, and one multiply from the engine's terms |
| `app/src/components/LongTextView.vue` | W2: the box, the side-by-side rows, the flip, and the picture beside it. It prints typed text as text, and never as HTML |
| `app/src/components/PicturePanel.vue` | W2: gains the side-by-side layout. Its reads do not change |
| `app/src/components/GhashView.vue`, `ForgeryView.vue` | W1c: the rows of section 2.4a, and the steps of section 2.4b. Values come from the engine |
| `app/src/useWalkTimeline.ts` | The one clock for timers and animations: Play, Pause, Resume, speed, stop at the end of a round, reduced motion. It holds states and never makes a byte |
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
| 4 | Key-pair bench, on a bench key made for the bench. It never signs with `ca-root` or a `Mine` key. Sign with the private key, and check with the public key. Change one byte, and the check fails. Sign with `attacker-ed25519`, and the check fails. The bench offers no "sign with the public key" button, and the text says why | One owner can sign, and anyone can check. A tag from lesson 1 could come from either side. Only a signature points at the sender | `Ed25519.Sign`, `Ed25519.Verify`. New route `POST /api/walk/signature` |
| 5 | Sees which job each part did: hybrid exchange (asymmetric), certificate signature (asymmetric), AES-GCM records (symmetric). Then presses **Measure**: AES on 1 MB, and repeated Ed25519 signs and X25519 mixes | Pairs set up the key and the shared key carries the data. The speed gap is a number from this machine, on the course's own table AES and not hardware AES. The label says both | `Modes.Ctr`, `Ed25519.Sign`, `X25519.Mult`. New route `POST /api/walk/speed` |
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
| W0 | This doc and Jared's review. **After Jared passes the head,** Echo writes clauses from sections 2 to 4, red | Jared's pass on a named head. Clauses exist and fail with a named code | Richard, Jared, Echo |
| **W1a** skeleton | `AesKey.Walk.cs` with word rows and MixColumns terms, `AesWalks.Block`, the tables route and the block route. No UI | FIPS, table, BCL, toggle, term, and golden clauses pass on both builds. `tools/gate.ps1` green | Richard |
| **SC** spec cards | `specs.json`, `SpecCard.vue`, `TextWithSpecs.vue`, `specParts`, the Electron link handler, and the table's rows for every spec on screen. It lands with the new look, before W1b, because it binds every screen | Spec card clauses. A15 and A15a on `specs.json` | Nancy, Richard, Jared on the table |
| **Hold on W1b** | Do not start the walk screens until the lead says the new look is set. Steve wants a major UX refresh. W1a is engine work, and it is not affected | | Lead |
| **W1b** small section | `walk.ts`, `useWalkTimeline.ts`, `AesBlockWalk.vue`, `SboxView.vue`, `KeySchedulePanel.vue`, `FieldPanel.vue`, `MixMatrixView.vue`, chapter 1 at 128 bits with animation, binary on hover, and typed text (`AesTypedBlocks`, `/typed-block`), encrypt and decrypt, the flip guard | e2e: a learner reaches `Pump four is ok.` by Next alone. A clicked cell's lookup equals the next state, both tables. Grid order clause. S-box scan. Measure the block reply time at AES-128 and AES-256, and record both in `docs/learnings.md`, because section 7 keeps one reply until this shows a visible delay | Nancy |
| **Stop: show Steve** | Steve steps through chapter 1 in the app and reacts. CBC and modes work starts after this | His reaction goes in `docs/learnings.md`, and later slices read it | Lead |
| **W1c** | `Gcm.CounterBlock`, `AesWalks.Feed`, the modes route, `AesFeedView.vue`, chapter 2 with ECB, CBC, GCM, and "Mistakes people make". `Gcm.WalkTag`, `Gf128.Inverse` and `SquareRoot`, `GcmForgeries`, `OptionForgeLastBlock`, the attack row, `/ghash`, `/forge`, `GhashView.vue`, `ForgeryView.vue`, `GcmStreamView.vue` (section 2.4d). Key sizes, two tour steps, gloss | Wire clauses per mode. e2e on wire match and on damage. A15, A15a by a reader who did not write it | Richard, Nancy |
| W2 | `AesKey.SboxBuild(byte)` and "how the table was built". `flipKeyBit`. `AesKey.DependsOn` and tap-a-byte. `AesLongText`, `/long-text`, `LongTextView.vue`, and the picture side by side. One-bit-flip spread count (4 bytes after round 1, 16 after round 2) | FIPS 5.1.1 worked example for `53`. Spread count against Jared's values | Richard, Nancy |
| W3 | Lesson 3 try-it, lesson 4 bench | Clauses on each check result | Richard, Nancy, Jared on wording |
| W4 | Lesson 5 record walk and speed bench | Record walk equals the wire. The number's label names the machine and table AES | Richard, Nancy |
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
| Round values | Every CIPHER and INVERSE CIPHER state for FIPS C.1, C.2, C.3, by position. The vector reader skips the appendix's EQUIVALENT INVERSE CIPHER lists, which hold a different order |
| Start view | At the start of encryption, the right-hand grid equals round key 0, and the first Next lands on AddRoundKey 0. At the start of decryption, it equals round key Nr, and the first Next lands on AddRoundKey Nr. After encrypt's last step, Next lands on the decrypt Start view, and the block equals `forward.output`. So the list holds one Start view before each direction's steps. It is gone with Show keys OFF |
| ShiftRows roll | The roll ends on the engine state. A Back during a roll leaves no strip and no hidden cell. Row 0 does not move |
| Phantom column | At each key size, a word has a phantom only on a RotWord or SubWord-only step, so w5 at AES-128 has none. Its cells equal `previous`, then `rotated`, `substituted`, and `afterRcon`, in that order. Each base column equals its `word` through every moment. A Back, a round chip, and Show keys OFF each leave no phantom. Pause holds it, by the Pause holds clause. Reduced motion shows none. The panel names `w(i - 1)` and `wi`, and the RotWord row reads "RotWord: rotate one byte, up this column" |
| Key fill | The lit `w(i - Nk)` byte equals `keyBack[j]`. On a word with no phantom, the lit `w(i - 1)` byte equals `previous` at byte j. On a word with a phantom, the phantom's lit byte equals the last stage's byte j, and the `previous` row lights the source position, which is `(j + 1) mod 4` on a RotWord step. The equation's three values equal the reply's. A Back mid-word leaves no mark and no flying byte |
| Spec table | Every `url` has a host in `hosts`, and every row has a synopsis that passes reading grade |
| Spec on screen | A scan of tour text, gloss, and copy finds each spec-shaped name in the table. At the end of each lesson walk, an e2e scan of the page finds no spec-shaped name outside a card trigger. A Host refusal naming RFC 8446 shows a card |
| Spec card | It opens on hover, focus, and tap. It stays open with the pointer on it. Esc closes it. Tour files keep their hash |
| Spec link | A new window is always denied, and so is `will-navigate`. A link opens outside only for `https:` and a listed host. A test URL on another host does not open, and `file://` with a listed host does not open |
| Expanded table | 11, 13, and 15 grids of 16 cells. The cell at byte position n shows byte n of the expanded key, and its word name is `w(n / 4)`. No cell shows a letter. The key band ends where section 2.2b says, and those cells start filled |
| Word build | Next adds one word. The lit cells equal that row's `previous` and `keyBack`. A tap on a built word opens its stage rows, and a tap on an unbuilt word does nothing. Each `aes-walk-*` key schedule cell is gone with Show keys OFF |
| Word test | On every row at all three sizes, `divisor` is Nk, and `divisor` x `quotient` + `remainder` equals `i`. `rotated` is set only when `i` is at or past Nk and `remainder` is 0. `substituted` alone is set only at AES-256 with `remainder` 4. W1a holds this part. In W1b, the panel prints those numbers in the sentence that matches the row's stages, for a RotWord word, a SubWord-only word, a plain word, and a key word. At AES-192, a word with remainder 4 reads plain |
| Key words | FIPS appendix A rows, for all three sizes. The Rcon row equals `01 02 04 08 10 20 40 80 1b 36`, and the used counts are 10, 8, 7 |
| AddRoundKey order | With motion on, the key grid equals the step's `roundKey` while the block still equals the state before the step, then the block changes. An AddRoundKey that runs from a Start view shows no fill, on encrypt and on decrypt. Every other one fills first, including one reached by a round chip, and decrypt's AddRoundKey 0. Pause holds the fill and the slide, by the Pause holds clause |
| End frames | Every animated step lands on the engine state for that step, for all three key sizes |
| Reduced motion | Each step shows its end frame with no transition |
| Pause holds | With motion on at the `slow` speed, Pause during a flying byte, a key fill, a phantom column, and a matrix multiply. The clause waits for each animation's `ready`, then samples. Each moving element's position stays the same for 2 seconds, within 1 pixel. At least one paused animation has a `currentTime` below its end. If nothing runs when the click lands, the clause repeats from the step before, and it reads NOT RUN after 3 tries |
| Resume carries on | Before the Resume click, a `requestAnimationFrame` sampler in the page logs `performance.now()` and each animation's `currentTime`. At the first frame after Resume, `currentTime` is at or above the paused value, below the end, and no further past the paused value than the elapsed page time plus 1 frame, times the speed. So the motion neither restarts nor jumps to the end. The motion then lands on the engine state |
| Pause label | The button reads Pause during a motion from one Next, Resume when frozen, and Play when nothing runs. Play still stops at the end of a round and of a grid |
| Next and Back while paused | Each ends the motion and acts. After Next, the next step's motion runs and the button reads Pause, and it lands on that step's engine state. Back leaves no flyer, strip, box, or mark. Play does not restart |
| Tips while paused | A hover tip and a spec card open while paused, and the moving elements stay still |
| Show keys while paused | Show keys OFF clears the walk, with no frozen flyer left and no timer that fires later |
| Key number | Each AddRoundKey button reads "AddRoundKey r", and r is the step's `round`. The grid it shows equals round key r. Encrypt counts up from 0, and decrypt counts down from Nr to 0, for all three key sizes |
| Rcon steps | The tables route sends 9 steps. Each `from` and `to` equal the neighbouring `rcon` values. Each `to` equals `shifted`, XOR `11b` when `reduced`, and `reduced` means `shifted` is past 8 bits. Only `80` to `1b` is reduced. W1a holds this clause, because the route is W1a |
| Rcon doubling | Play builds 10 values from `01` at each key size and stops. The bit rows print the step's values. `80` to `1b` shows the break-away and the XOR 1b row. 10, 8, and 7 values show undimmed. Pause holds the rows, by the Pause holds clause |
| Rcon compact row | On each RotWord word, the lit value equals the first byte of that row's `rcon`. A SubWord-only word and a plain word light none |
| Shift map | `state[i]` after ShiftRows equals `state[map[i]]` before it, using the map the tables route sends |
| Matrix view | The lit row's factors and the flown column equal the part's `factor` and `input`. The landed byte equals the state after. Tapping a byte picks its column. Fill all equals the state after. A Back during Play leaves no flyer, box, or lit row. InvMixColumns shows 14, 11, 13, 9 |
| Overflow rows | On every doubling, `to` equals `shifted`, XOR `11b` when `reduced`, and `reduced` means `shifted` is past 8 bits. An overflow shows the break-away and the XOR 1b row. The last `running` equals `result`, and the last `sums` equals the part's `result` |
| ShiftRows colours | On ShiftRows, the marked cells are the staircase at the right. On InvShiftRows, it is at the left. Each marked byte is one that wrapped, by the shift map |
| Field terms | The XOR of the terms equals the state byte, in every round, both directions. `d4 bf 5d 30` gives `04 66 81 e5` |
| Definition | Lines 1 to 5 of section 2.2c appear, and pass the reading-grade clause |
| Step counts | 40, 48, 56 per direction. The last encrypt round has no MixColumns. The decrypt order is section 5.3's |
| S-box | Both tables equal FIPS Tables 4 and 6 on all 256 entries. `53` gives `ed`, and row `e`, column `d` of the inverse gives `53`. The route answers with Show keys OFF |
| S-box view | A clicked cell's row, column, and table value equal the next state's cell, on SubBytes and InvSubBytes |
| Real run | Key and block from a live session's trace, with the BCL as referee on the walk's output |
| Modes | `match` on every row: `TextGcm1` 4, `TextCbc` 5, `PictureEcb` capped rows, `TextEcb` 5 on the fork. `unlockPass` is inverse for ECB and CBC, forward for GCM. Call counts per section 2.4 |
| Damage | `L1-flip-cbc` gives `differs` and the 16, 1, 0, 0, 0 pattern. `L1-flip-gcm` gives `differs`, a failed tag, and no unlock bytes. Free flips: CBC IV gives `damage: iv` with block 1's bit flipped. GCM nonce and tag give all `match`, the named `damage`, and a failed tag. A header flip gives no unlock. A `TextCbc` type flip with xor 10 gives `damage: type`, and the run completes with no failed check. The lock column shows the sender's starter in each case. A free wire flip, addressed by stream, recovers the sender's frame. A failed run can cut the client's burst short, so a clause on a later message in a flip fork allows a row result or `WALK_MESSAGE_NOT_SENT` |
| Tag per message | A flip on `PictureGcm` leaves `TextGcm1`'s tag as `passed` |
| GCM stream | On `TextGcm1`, each `count` runs from 2, and each `lockIn` ends in that count. Byte j of `cipher` equals byte j of `data` XOR byte j of `lockOut`, checked by the clause and never by the app. The panel prints those bytes. Next moves one byte, and Show all shows the engine's rows. Pause holds the motion. With Show keys OFF, the stream stays and the tag section closes. Every GCM message in lesson 1 fills its blocks, so a pure test on `AesWalks.Feed` holds the unused-byte rule: on a run's key, a 25-byte text's last `lockOut` holds 9 bytes |
| GCM flip | `flip.computedTag` differs from `tag`, and it equals the BCL's tag on `flip.cipher`. `flip.textWithoutTag` differs from the text at one bit, the bit `flip` names. The trace gets no event from it. Off with Show keys OFF, with `/ghash` |
| GHASH | Each row is XOR then multiply. `Tag` equals the frame's tag on `TextGcm1`, and on a message with the BCL as referee. H equals AES of the zero block. The nonce is not an input to a row |
| Forgery recovery | Recovered H equals AES of the zero block under the run's key, on 2 seeds. Section 2.4b's table holds |
| Forgery accepted | `Gcm.TryOpen` accepts the forged message and returns the forged text. A one-bit change to the forged tag fails it |
| Forgery refusals | Same text twice gives `WALK_FORGE_SAME_TEXT`, never a divide by zero or a wrong H. Two nonces give `WALK_FORGE_NONCE_DIFFERS`, with no H. More than the last block differing, only an earlier block differing, and different lengths each give `WALK_FORGE_TOO_MANY_BLOCKS` |
| Forgery reads no key | `GcmForgeries.Recover` takes frames and known text only. A test calls it with no key in scope |
| Control unchanged | The control's golden is unchanged with the new option in the code. No forgery value enters a trace or session file |
| Binary tip | Each tip's bits equal the cell's hex. Before and after equal the engine's two states, and the count equals the differing bits. On ShiftRows, a cell in rows 1, 2, 3 names its source from the shift map, a cell in row 0 says it stayed, and neither shows a change. A value past 16 bytes says how many more |
| Typed block | Under 16 bytes pads with n bytes of value n, equal to `Lesson01Aes.Pad`'s last block. 16 bytes adds none. A longer text uses the first 16 bytes, and `notIncluded` counts the rest. A 2-, 3-, and 4-byte character across byte 16 gives the right `splitBytesIn`, and the walk ends on those 16 bytes. The default text walk is unchanged |
| Long text (W2) | Every ECB and CBC block equals the BCL under the practice key and IV. ECB changes the flipped block only. CBC changes that block and all later ones. A flip in the last block changes one. Repeat counts are blocks minus distinct blocks, equal to a count from the BCL's blocks. A flip in padding gets `WALK_BAD_ARGUMENT`. `FlippedRows` is null with no flip |
| Typed limits | 65,536 bytes passes, and 65,537 gives `WALK_TEXT_TOO_LONG`. Empty gives `WALK_TEXT_EMPTY`. A lone surrogate gives `WALK_TEXT_INVALID`. Both typed routes answer with Show keys OFF. The practice key differs from the run's key, and no typed reply holds a run's key byte: a typed block of 16 zero bytes does not give the run's H. Clearing the box with Show keys OFF closes the walk again. `keySource` reads `typed-practice`. Nothing typed reaches a trace, session file, or `/events`. Typed `<b>` shows as text. The goldens stay unchanged |
| Picture (W2) | The side-by-side counts equal the run's `measure.result`. The eavesdropper view hides the clear picture |
| Tap a byte (W2) | The flip test of section 2.2e, on every step and cell |
| Bug versus tamper | A session with no plan never reads `differs`. A unit test gives `Feed` a wrong sender frame, and it throws `AES_WALK_DIVERGED`. A free flip on a non-wire event reads all `match` |
| Box rows | `/block` answers for every row of `/modes`, including the padding row, and gives 400 one past it |
| Label | A control run's `source=text` reply says `notSent`, and the panel shows the teaching-example label |
| Real path | `WalkEncrypt` equals `EncryptBlock` on 10,000 random inputs |
| Toggle | OFF gives 409 `KEYS_HIDDEN` on `/block`, with no bytes in the error, so no word row or term leaves. A flip during Play stops the timeline. `/modes` and the tables answer OFF, and a `/modes` reply holds no key byte and no round state. Every field recomputes from `plain` and `wire` |
| Key-bearing routes | A clause lists each walk route and its OFF behaviour, and each reply has `Cache-Control: no-store`. A new route must join the list |
| Flip race | The block walk clears when `sec.showKeys` goes false and when the socket closes, with the flip frame dropped on purpose. A late reply is dropped. No state reaches a session file |
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

**The arithmetic.** One learner, at most about 1 walk query per second while picking blocks. A block reply is about 5 to 7 KiB of states and key words. The MixColumns terms add 1,152 terms at AES-128 and 1,664 at AES-256. With the matrix view's fields, a spike's count of the JSON gives about 235 KiB at AES-128 and 340 KiB at AES-256. That is a large reply for one click, and it is still small for a local socket, so the design sends it whole and keeps no second query. W1b measures it. A visible delay would move the terms to a query per step. A feed reply holds at most 5 rows. The tables reply is about 1.6 KiB by estimate, fetched once. A walk costs about 6 microseconds in this test environment, against about 0.5 microseconds for `EncryptBlock`. Storage over three years is zero, since nothing is stored. So the design uses no cache, no streaming, and no per-step request. One reply holds the whole walk, and Next is a local move.

**Gem catalog.** I read `E:\dev\MMP.ProgrammingGems\INDEX.md`.

| Gem | Use |
|---|---|
| `decide-at-authoritative-boundary` | Applies. The Host decides the toggle and the facts, once, at the route. Mark `AesWalkRoutes` |
| `server-replaces-never-merges` | Applies. The app replaces the whole walk on each reply and clears it on a flip. Mark `walk.ts` |
| A new gem? | No gem covers "an instrumented twin of a hot path, checked against the real path on every call". One use site so far. I record it as a candidate at W5, with Jared as SME, if the second walk type uses it too |

**CrypTool, "AES (step-by-step)" on CrypTool-Online,** https://www.cryptool.org/en/cto/aes-step-by-step , which redirects to https://legacy.cryptool.org/en/cto/aes-step-by-step . Read 2026-11-06. It offers "Tap on each byte to see the bytes it depends on", and it shows encode and decode rounds. Took: the tap idea. We took no code, and the page states a copyright notice with no licence. Where we differ: our rule comes from the engine and a clause flips real bytes to check it. Its page does not mention a jump to a round, so that control is ours.

**CrypTool 2, the "Block Modes" template.** Source: `E:/dev/refs/CrypTool-2/documentation/images/blockmode_visualization.png`, read 2026-11-06. It shows a picture under AES with ECB and with CBC, side by side. Took: the side-by-side idea, with repeats marked. Where we differ: we add a typed text, a flip with counts, and engine values, and we use our own picture. We took no code or image.

**CUPID, under pressure.** Predictable is the property most at risk, because a twin path can drift. The run-time guard answers that. Composable holds: `AesWalks` is pure, and lessons 5 and 7 reuse it. Domain-based holds: the types use the FIPS step names. Complexity hotspots: `describeStep` wants a lookup by step kind, and each Vue file stays thin because `walk.ts` holds the logic. SOLID adds nothing here.

## 8. Non-goals

1. No walk of SHA-256 rounds or the X25519 ladder in the pilot. GHASH shows each multiply as one step, and its 128 shifts stay out.
2. No CFB, OFB, or XTS. No CTR tab in lesson 1. No root finding: the forgery covers a change in the last block only.
3. No walk on a loaded replay or an OS transport session.
4. No change to `EncryptBlock`, `DecryptBlock`, or `CounterCrypt`.
5. No claim that this AES is production AES. `AesKey.cs:8` already says that table lookups can leak through a CPU cache, and the panel says so too.

## Disposition

Ready for Jared's review on the crypto wording and sections 1.1, 2.4, 2.5, 3.5, 3.6, and 5. Echo writes clauses after Jared passes the head. Do not start W1a until both are done.
