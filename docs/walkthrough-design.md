# MMP.NetworkSecurity: walkthrough design

Author: Richard. Date: 2026-11-06. Revision 6, adding Steve's rulings: jump to a round, tap a byte, the GHASH walk, and the forgery demo. Status: design only, for Jared's check and Echo's clauses. No product code.

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
| AddRoundKey | Each byte is XORed with the round key. This is the only step that uses the key. It is its own inverse | State, round key, result |
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
| AddRoundKey | The round key grid slides over the state. Each cell shows its new byte | Engine state after AddRoundKey |
| SubBytes | Each cell flips to its new byte, one cell at a time on the first pass, then all cells at once | Engine state after SubBytes |
| ShiftRows | Row 0 stays. Rows 1, 2, 3 slide left by 1, 2, 3 and wrap around | Engine state after ShiftRows |
| MixColumns | One column at a time lifts, its 4 bytes join, and 4 new bytes come out | Engine state after MixColumns |
| Inverse steps | The same motion, in the inverse direction | Engine state after the inverse step |

| Detail | Rule |
|---|---|
| Where a byte came from | Each cell shows a small mark with its position before this step, 0 to 15. The marks reset at each step, because a byte has no single source after MixColumns |
| Which way ShiftRows moves | The engine's `ShiftRowsMap` and `InverseShiftRowsMap` come from the tables route (section 3.4), so a motion cannot disagree with the real map |
| Next and Back | They land on the same states as without animation. A click during a motion jumps to the end frame |
| `prefers-reduced-motion` | Each step jumps to its end frame |
| Show keys flips OFF during a motion | The timeline stops, and the walk clears (section 3.5) |
| Library | None. CSS transforms and one small composable, `useWalkTimeline`. I would add a library only if a transform cannot do the MixColumns join |

For tests: a clause reads end frames under reduced motion, so no test waits on a timer.

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

**At AES-192 and AES-256, the key runs past round key 0.** The grids stay one per round key, because each grid is what one AddRoundKey uses. A band marks the key's words across the grids: `w0` to `w5` at AES-192, and `w0` to `w7` at AES-256. Those cells start filled, and the panel says: "The first 6 words are the key, so round key 1 starts with key bytes." At AES-256 it says the first 8 words. The build starts at the next column: `w6` at AES-192, and `w8` at AES-256.

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

**The reply needs no new field.** `keyWords[]` already has every row by `i`, and each row holds `word`, `previous`, `rotated`, `substituted`, `rcon`, `afterRcon`, and `keyBack`. Grid, column, cell, and byte position come from `i` by layout: `i / 4`, `i % 4`, and `4i + r`. The two words to light are `i - 1` and `i - Nk`, with Nk from the tables route's size table. That is position arithmetic, and the app reads no byte value to do it. A clause holds it: the bytes in the lit cells must equal `previous` and `keyBack`.

**Rcon row.** `01 02 04 08 10 20 40 80 1b 36`. Each value is the one before it, doubled in the field. Ordinary doubling of `80` gives `100`, which does not fit in a byte. Field doubling gives `1b`. This row is the first place the learner meets the field in real use. The row comes from the tables route, because the app holds no crypto values.

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
| Move through steps | Back, Next, and round chips to jump |
| Watch steps move | One Play and Pause button, which stops at the end of the round. Press it again for the next round. Steve can overrule this after he steps through W1b |
| How fast | One speed control: slow, normal, fast |
| See one word's build | Tap a built word in the table |
| See one byte's lookup | Click a cell |
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
  public sealed class GhashWalk { public readonly byte[] Hash, CounterBlock, Mask, Tag; public readonly GhashRow[] Rows; }
  public sealed class AesKeyWord {            // One row of the FIPS 197 appendix A tables. An unused cell is null
    public readonly int Index;
    public readonly byte[] Previous, Rotated, Substituted, Rcon, AfterRcon, KeyBack, Word;
  }
  public sealed class AesTerm {               // One factor x input term of a mixed byte
    public readonly int Factor;               // 2, 3, 1 or 14, 11, 13, 9
    public readonly byte Input;
    public readonly byte[] Doublings;         // Input x2, x4, x8, as far as the factor needs. The inverse factors need 3
    public readonly bool Reduced;             // Any doubling needed the reduction by 11b
    public readonly byte Result;
  }
  public sealed class AesColumnByte { public readonly AesTerm[] Terms; public readonly byte Result; }   // Result is the XOR of the terms
  public sealed partial class AesKey {
    public AesBlockWalk WalkEncrypt(byte[] block);   // Throws AES_WALK_DIVERGED if it differs from EncryptBlock
    public AesBlockWalk WalkDecrypt(byte[] block);   // Throws AES_WALK_DIVERGED if it differs from DecryptBlock
    public AesKeyWord[] WalkKeyExpansion();          // Nb * (Nr + 1) rows
    public static byte[] SubstitutionTable();        // A copy of Sbox, 256 bytes
    public static byte[] InverseSubstitutionTable(); // A copy of InverseSbox, 256 bytes
    public static int[] ShiftMap(bool inverse);      // A copy of ShiftRowsMap or InverseShiftRowsMap
    public static int[] DependsOn(AesStepKind kind, int cell);   // W2. The earlier cells this cell depends on (section 2.2e)
    public static byte[] RoundConstants(int count);  // Each value is the one before it, doubled in the field
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
    public byte[] LockIn, LockOut;            // Into and out of forward AES
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

`Gcm.CounterBlock` is new and pure. `CounterCrypt` stays as it is. The lock guard catches a drift between the two. `Lesson01Aes.Pad` changes from private to internal, so the feed uses the lesson's own padding. Its bytes and the lab's trace stay as they are. `ErrorCodes` gains `AesWalkDiverged`, `WalkNotBuilt`, `WalkWaitingForWire`, `WalkMessageNotSent`, `WalkMessageReplaced`, `WalkKeySizeNotInRun`, `WalkBadArgument`, `WalkForgeSameText`, `WalkForgeNonceDiffers`, and `WalkForgeTooManyBlocks`.

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
```

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
{ "sbox": "637c777b...", "inverseSbox": "52096ad5...", "shiftRows": [0, 5, 10, 15, "..."], "inverseShiftRows": [0, 13, 10, 7, "..."], "rcon": "01020408102040801b36",
  "sizes": [ { "keyBits": 128, "keyWords": 4, "rounds": 10, "roundKeys": 11, "words": 44, "rconUsed": 10 } ] }

// /block?source=text
{
  "source": "text", "keyBits": 128, "rounds": 10, "keySource": "run",
  "inputHex": "50756d7020666f7572206973206f6b2e",
  "keyWords": [ { "i": 4, "previous": "...", "rotated": "...", "substituted": "...", "rcon": "...", "afterRcon": "...", "keyBack": "...", "word": "..." } ],
  "forward": { "input": "...", "output": "...", "steps": [ { "kind": "AddRoundKey", "round": 0, "state": "...", "roundKey": "..." },
                                                 { "kind": "MixColumns", "round": 1, "state": "...", "terms": [ { "result": "04", "parts": [ { "factor": 2, "input": "d4", "doublings": ["b3"], "reduced": true, "result": "b3" } ] } ] } ] },
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
| A bad mode, source, block, or key size | 400 `WALK_BAD_ARGUMENT` |
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
| `app/src/components/KeySchedulePanel.vue` | The key as words, the expanded table of grids, one word's stage rows, the Rcon row |
| `app/src/components/FieldPanel.vue` | The definition lines, and one multiply from the engine's terms |
| `app/src/components/GhashView.vue`, `ForgeryView.vue` | W1c: the rows of section 2.4a, and the steps of section 2.4b. Values come from the engine |
| `app/src/useWalkTimeline.ts` | Play, Pause, speed, stop at the end of a round, reduced motion. It holds states and never makes a byte |
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
| **Hold on W1b** | Do not start the walk screens until the lead says the new look is set. Steve wants a major UX refresh. W1a is engine work, and it is not affected | | Lead |
| **W1b** small section | `walk.ts`, `useWalkTimeline.ts`, `AesBlockWalk.vue`, `SboxView.vue`, `KeySchedulePanel.vue`, `FieldPanel.vue`, chapter 1 at 128 bits with animation, encrypt and decrypt, the flip guard | e2e: a learner reaches `Pump four is ok.` by Next alone. A clicked cell's lookup equals the next state, both tables. Grid order clause. S-box scan. Measure the block reply time at AES-128 and AES-256, and record both in `docs/learnings.md`, because section 7 keeps one reply until this shows a visible delay | Nancy |
| **Stop: show Steve** | Steve steps through chapter 1 in the app and reacts. CBC and modes work starts after this | His reaction goes in `docs/learnings.md`, and later slices read it | Lead |
| **W1c** | `Gcm.CounterBlock`, `AesWalks.Feed`, the modes route, `AesFeedView.vue`, chapter 2 with ECB, CBC, GCM, and "Mistakes people make". `Gcm.WalkTag`, `Gf128.Inverse` and `SquareRoot`, `GcmForgeries`, `OptionForgeLastBlock`, the attack row, `/ghash`, `/forge`, `GhashView.vue`, `ForgeryView.vue`. Key sizes, two tour steps, gloss | Wire clauses per mode. e2e on wire match and on damage. A15, A15a by a reader who did not write it | Richard, Nancy |
| W2 | `AesKey.SboxBuild(byte)` and "how the table was built". `flipKeyBit`. `AesKey.DependsOn` and tap-a-byte. One-bit-flip spread count (4 bytes after round 1, 16 after round 2) | FIPS 5.1.1 worked example for `53`. Spread count against Jared's values | Richard, Nancy |
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
| Expanded table | 11, 13, and 15 grids of 16 cells. The cell at byte position n shows byte n of the expanded key, and its word name is `w(n / 4)`. No cell shows a letter. The key band ends where section 2.2b says, and those cells start filled |
| Word build | Next adds one word. The lit cells equal that row's `previous` and `keyBack`. A tap on a built word opens its stage rows, and a tap on an unbuilt word does nothing. Each `aes-walk-*` key schedule cell is gone with Show keys OFF |
| Key words | FIPS appendix A rows, for all three sizes. The Rcon row equals `01 02 04 08 10 20 40 80 1b 36`, and the used counts are 10, 8, 7 |
| End frames | Every animated step lands on the engine state for that step, for all three key sizes |
| Reduced motion | Each step shows its end frame with no transition |
| Shift map | `state[i]` after ShiftRows equals `state[map[i]]` before it, using the map the tables route sends |
| Field terms | The XOR of the terms equals the state byte, in every round, both directions. `d4 bf 5d 30` gives `04 66 81 e5` |
| Definition | Lines 1 to 5 of section 2.2c appear, and pass the reading-grade clause |
| Step counts | 40, 48, 56 per direction. The last encrypt round has no MixColumns. The decrypt order is section 5.3's |
| S-box | Both tables equal FIPS Tables 4 and 6 on all 256 entries. `53` gives `ed`, and row `e`, column `d` of the inverse gives `53`. The route answers with Show keys OFF |
| S-box view | A clicked cell's row, column, and table value equal the next state's cell, on SubBytes and InvSubBytes |
| Real run | Key and block from a live session's trace, with the BCL as referee on the walk's output |
| Modes | `match` on every row: `TextGcm1` 4, `TextCbc` 5, `PictureEcb` capped rows, `TextEcb` 5 on the fork. `unlockPass` is inverse for ECB and CBC, forward for GCM. Call counts per section 2.4 |
| Damage | `L1-flip-cbc` gives `differs` and the 16, 1, 0, 0, 0 pattern. `L1-flip-gcm` gives `differs`, a failed tag, and no unlock bytes. Free flips: CBC IV gives `damage: iv` with block 1's bit flipped. GCM nonce and tag give all `match`, the named `damage`, and a failed tag. A header flip gives no unlock. A `TextCbc` type flip with xor 10 gives `damage: type`, and the run completes with no failed check. The lock column shows the sender's starter in each case. A free wire flip, addressed by stream, recovers the sender's frame. A failed run can cut the client's burst short, so a clause on a later message in a flip fork allows a row result or `WALK_MESSAGE_NOT_SENT` |
| Tag per message | A flip on `PictureGcm` leaves `TextGcm1`'s tag as `passed` |
| GHASH | Each row is XOR then multiply. `Tag` equals the frame's tag on `TextGcm1`, and on a message with the BCL as referee. H equals AES of the zero block. The nonce is not an input to a row |
| Forgery recovery | Recovered H equals AES of the zero block under the run's key, on 2 seeds. Section 2.4b's table holds |
| Forgery accepted | `Gcm.TryOpen` accepts the forged message and returns the forged text. A one-bit change to the forged tag fails it |
| Forgery refusals | Same text twice gives `WALK_FORGE_SAME_TEXT`, never a divide by zero or a wrong H. Two nonces give `WALK_FORGE_NONCE_DIFFERS`, with no H. More than the last block differing, only an earlier block differing, and different lengths each give `WALK_FORGE_TOO_MANY_BLOCKS` |
| Forgery reads no key | `GcmForgeries.Recover` takes frames and known text only. A test calls it with no key in scope |
| Control unchanged | The control's golden is unchanged with the new option in the code. No forgery value enters a trace or session file |
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

**The arithmetic.** One learner, at most about 1 walk query per second while picking blocks. A block reply is about 5 to 7 KiB of states and key words. The MixColumns terms add 1,152 terms at AES-128 and 1,664 at AES-256, at about 40 bytes each by estimate, so about 46 to 67 KiB more. That is a large reply for one click, and it is still small for a local socket, so the design sends it whole and keeps no second query. A feed reply holds at most 5 rows. The tables reply is about 1.1 KiB, fetched once. A walk costs about 6 microseconds in this test environment, against about 0.5 microseconds for `EncryptBlock`. Storage over three years is zero, since nothing is stored. So the design uses no cache, no streaming, and no per-step request. One reply holds the whole walk, and Next is a local move.

**Gem catalog.** I read `E:\dev\MMP.ProgrammingGems\INDEX.md`.

| Gem | Use |
|---|---|
| `decide-at-authoritative-boundary` | Applies. The Host decides the toggle and the facts, once, at the route. Mark `AesWalkRoutes` |
| `server-replaces-never-merges` | Applies. The app replaces the whole walk on each reply and clears it on a flip. Mark `walk.ts` |
| A new gem? | No gem covers "an instrumented twin of a hot path, checked against the real path on every call". One use site so far. I record it as a candidate at W5, with Jared as SME, if the second walk type uses it too |

**CrypTool, "AES (step-by-step)" on CrypTool-Online,** https://www.cryptool.org/en/cto/aes-step-by-step , which redirects to https://legacy.cryptool.org/en/cto/aes-step-by-step . Read 2026-11-06. It offers "Tap on each byte to see the bytes it depends on", and it shows encode and decode rounds. Took: the tap idea. We took no code, and the page states a copyright notice with no licence. Where we differ: our rule comes from the engine and a clause flips real bytes to check it. Its page does not mention a jump to a round, so that control is ours.

**CUPID, under pressure.** Predictable is the property most at risk, because a twin path can drift. The run-time guard answers that. Composable holds: `AesWalks` is pure, and lessons 5 and 7 reuse it. Domain-based holds: the types use the FIPS step names. Complexity hotspots: `describeStep` wants a lookup by step kind, and each Vue file stays thin because `walk.ts` holds the logic. SOLID adds nothing here.

## 8. Non-goals

1. No walk of SHA-256 rounds or the X25519 ladder in the pilot. GHASH shows each multiply as one step, and its 128 shifts stay out.
2. No CFB, OFB, or XTS. No CTR tab in lesson 1. No root finding: the forgery covers a change in the last block only.
3. No walk on a loaded replay or an OS transport session.
4. No change to `EncryptBlock`, `DecryptBlock`, or `CounterCrypt`.
5. No claim that this AES is production AES. `AesKey.cs:8` already says that table lookups can leak through a CPU cache, and the panel says so too.

## Disposition

Ready for Jared's review on the crypto wording and sections 1.1, 2.4, 2.5, 3.5, 3.6, and 5. Echo writes clauses after Jared passes the head. Do not start W1a until both are done.
