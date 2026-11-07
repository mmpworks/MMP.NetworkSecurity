# Lesson 1 fact sheet: symmetric, asymmetric, and the AES modes

For: Richard (lesson 1 tour rewrite). From: Jared. Checked against `MMP.NetworkSecurity` main `7b569a1`.
Engine source for lesson 1: `src/NetSec.Core/Labs/Lesson01Aes.cs`. GCM source: `src/NetSec.Core/Crypto/Gcm.cs`.

## Two changes I would make first

1. Name lesson 1 as **symmetric** encryption in step L1-S02. That step already shows one key on both sides. It is the natural place.
2. In step L1-S08, add one line: the tag proves "someone who holds the shared key made this". It cannot say which side. A signature (lesson 4) can. This line is the bridge to asymmetric.

## 1. Symmetric and asymmetric, in eighth-grade words

### Symmetric: one shared key

- One key does both jobs. The same key locks the data and unlocks it.
- Both sides must hold a copy of that one key. Anyone else who gets a copy can read everything.
- It is fast. It can lock megabytes of data.
- It can also seal data with a tag. The tag shows that someone who holds the key made the message.
- Weak point: how do two strangers get the same key, when anyone can listen to the wire?

**What the course shows:** lesson 1. The lab draws one random 16-byte AES-128 key and gives the same bytes to the client and the server (`Lesson01Aes.cs:64-72`). No key crosses the wire in lesson 1. The lab skips the "how do we share it" problem on purpose. Step L1-S02 already says so and points to lesson 3.

### Asymmetric: a key pair

- Each side makes a pair of keys: a **private key** and a **public key**.
- The private key never leaves its owner. The public key is safe to give to anyone.
- You cannot work back from the public key to the private key.
- It is slow, compared to symmetric. Systems use it for small jobs only.
- It does three jobs in this course (table below). None of them is "lock the bulk data".

| Job | What happens | Where the course shows it |
|---|---|---|
| Agree on a shared key | Each side mixes its own private key with the other side's public share. Both sides reach the same secret. That secret never crosses the wire. | Lesson 3: X25519, ML-KEM-768, and the hybrid of the two (`Lesson03Kex.cs`) |
| Prove who you are (sign) | The owner signs with the private key. Anyone with the public key can check the signature. Nobody else can make one. | Lesson 4: the training CA signs certificates with Ed25519 (`TrainingCa.cs:10`). The server signs the handshake in CertificateVerify (scheme 0x0807, Ed25519). |
| Put a key in a box | The client locks a fresh secret with the server's public key. Only the server's private key opens it. | Lesson 7, step L7-S05 "The key travels in a box" (TLS 1.1 RSA key transport). This is the only place where a lesson shows public-key encryption by that name. ML-KEM also encrypts inside, on a random value (section 5.10). |

Note on ML-KEM (lesson 3): it is a "box" too. The client publishes an open box (the 1,184-byte encapsulation key). The server puts a random secret in it (the 1,088-byte ciphertext). Only the client opens it. The tour already uses this picture in L3-S06 and L3-S07.

### Why real systems use both

- Asymmetric solves the problem symmetric cannot: two strangers reach a shared key in public, and one side proves who it is.
- Symmetric does the heavy work: it locks and seals every byte of real data, fast.
- So the order in TLS and SSH is: asymmetric first, to set up a key. Then symmetric, to carry the data under that key. Lesson 6 (DUKPT) is the exception: it uses symmetric keys only.

**What the course shows:** lesson 5 (TLS 1.3). The hybrid exchange (lesson 3 math) makes the shared secret. Ed25519 signatures (lesson 4 math) prove the server. Then the keys feed AES-GCM (lesson 1 math) for every sealed record. The suites are `TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384` (`Tls13Suite.cs:21-22`). L5-S01 already lists the three jobs in this order.

## 2. Facts lesson 1 must get right (as the engine runs them)

### The key

- AES-128. The key is 16 random bytes (`Lesson01Aes.cs:64-65`).
- The same key bytes go to both sides. The secrets panel shows it in both lanes. That is correct for symmetric.

### The messages, in order

The client sends six messages in one burst (`ClientSendAll`, lines 94-109):

1. `TextGcm1`: the text, GCM.
2. `TextCbc`: the text, CBC. With the `L1-use-ecb` attack, this is `TextEcb` instead.
3. `PictureEcb`: the picture, ECB.
4. `PictureCbc`: the picture, CBC.
5. `PictureGcm`: the picture, GCM.
6. `TextGcm2`: the text, GCM. With the `L1-reuse-nonce` attack, it reuses the nonce of message 1.

The text is 64 bytes: "Pump four is ok." four times. Each copy fills one 16-byte block, so the text has four equal blocks (line 37).
The picture is a 64 x 64 fuel pump, one byte per pixel, 4,096 bytes (lines 244-259).

### GCM

- Wire layout: 12-byte nonce, then the ciphertext, then a 16-byte tag (lines 165-170).
- The ciphertext has the same length as the plaintext. GCM adds no padding.
- No extra data (AAD) is covered in lesson 1. The AAD is empty.
- The nonce and the tag travel in the clear. They are not secrets. The eavesdropper sees both. L1-S03 is correct on this.
- The receiver checks the tag **first**. If the tag fails, it returns no plaintext at all (`Gcm.cs:40-45`). The comparison is constant-time. Claim L1-C02 matches the code.
- The tag is made with the shared key. So the tag shows "someone with this key made it, and nobody changed it". Either side could have made it. The tag says nothing about which side.
- Inside GCM, AES locks a counter, and the result is mixed into the data. AES does not lock the data blocks directly in GCM. (The glossary "block" entry says "AES locks data one block at a time". That is true for ECB and CBC. It is loose for GCM. Optional fix.)

### The nonce reuse detector

- The server runs two checks on each GCM message, in this order: the tag, then the detector (lines 128-140).
- On the reuse run, message 6 has a **valid** tag. The tag check passes. Only the detector fails. Do not write that "the tag catches the reused nonce".
- The detector is a lab feature. Real GCM has no alarm for a reused nonce. The tour says this in L1-S09 and claim L1-C04. Keep it.
- What a reuse leaks: two messages under one key and one nonce share a key stream. XOR of the two ciphertexts gives XOR of the two plaintexts. A repeat can also leak the hash key, which lets an attacker forge tags (SP 800-38D, Appendix A). "Compare two messages and forge new ones" (L1-S09) is correct.
- GCM needs a nonce that is **unique** per key. Random is one way to get unique. A counter is another (TLS 1.3 uses a record counter). Do not write "the nonce must be random".

### CBC

- Wire layout: 16-byte random IV, then the ciphertext (lines 158-163).
- The data is padded to a whole number of blocks first. The 64-byte text gets one full extra block of padding, so it sends five blocks.
- The IV is in the clear. It is not secret. For CBC it must be unpredictable, which is stronger than "used once".
- CBC has **no check**. A flipped bit never fails a check in lesson 1 (lines 172-185).
- Flip one ciphertext bit in block N: block N of the plaintext turns to junk, and block N+1 flips that same bit. Claim L1-C05 matches.
- Edge cases the tour does not need to state, but must not contradict: a flip in the IV changes only block 1, with no junk block. A flip in the last block can break the padding. The engine then keeps the bytes as they are (`Unpad`, lines 226-232). There is no padding check, so no padding error appears.

### ECB

- No IV, no nonce, no check. The data is padded, then each 16-byte block is locked alone (lines 152-156).
- Equal plaintext blocks give equal ciphertext blocks. That is the leak. Claim L1-C01 matches.
- AES itself is not broken here. The mode is the weak part. L1-S06 says this. Keep it.

### The repeat count

- The server counts repeated 16-byte cipher blocks. It skips the nonce and tag (GCM) or the IV (CBC) first (lines 197-207).
- The trace event reads `repeats=R;blocks=B`.
- Text in ECB: 5 blocks, 3 repeats (the four equal text blocks give 3 repeats; the padding block is unique).
- Picture in ECB: 257 blocks with a large repeat count.
- Picture in CBC (257 blocks) and GCM (256 blocks, no padding): the count is 0 in practice. "Near zero" in L1-S06 and L1-S07 is safe wording.

## 3. Wrong statements a beginner text makes

Avoid each of these. The right version follows each one.

| Wrong | Right |
|---|---|
| "The public key decrypts." / "Signing is encrypting with the private key." | A public key checks a signature, or locks a box that only the private key opens. Ed25519 (the course's signer) has no encrypt step at all. Keep "sign" and "lock" as separate verbs. |
| "Encryption proves who sent it." | Encryption hides data. It proves nothing about the sender. |
| "The GCM tag proves the server sent it." | The tag proves that someone who holds the shared key made it. Both sides hold that key. Only a signature points at one owner. |
| "Asymmetric is more secure than symmetric." | They do different jobs. AES-128 is strong. Asymmetric is slower and covers key setup and proof of identity. |
| "Real systems lock the data with the public key." | The bulk data uses a symmetric lock (AES-GCM in lessons 1 and 5). The public-key part only sets up the key. |
| "The key exchange sends the key across the wire." | In X25519 no key crosses the wire. Each side computes the same secret. (In RSA key transport, lesson 7, the secret does cross, inside a box.) |
| "You can work out the private key from the public key." | You cannot, for the keys in this course. That is the point of a key pair. (A large quantum computer could do it for X25519 and Ed25519 in future. Lesson 3 covers that. Keep it out of lesson 1.) |
| "The nonce, IV, and tag are secret." | All three travel in the clear. Only the key is secret. |
| "The nonce must be random." | The GCM nonce must be unique under one key. The CBC IV must be unpredictable. |
| "The tag catches a reused nonce." | The tag passes on a reused nonce. Only the lab detector catches it, and real GCM has no detector. |
| "GCM unlocks the data, then checks the tag." | The engine checks the tag first and returns nothing on a failure. SP 800-38D lists the tag step last and permits either order. The rule is that no plaintext comes out on a failure. |
| "ECB uses a weak key." / "ECB breaks AES." | The key and AES are fine. The mode leaks patterns. |
| "CBC catches edits." / "The padding catches a flipped bit." | CBC has no check. In this lab a flip passes with no error. |
| "Hashing is encryption." | A hash has no key and cannot be undone. Lesson 2 covers seals (HMAC, CMAC). |

Two glossary entries in `app/src/glossary.json` conflict with the new step. They are worth a fix in the same PR:

- `key`: "A secret number that locks and unlocks data." This is true only for a symmetric key. A public key is not secret, and a signing key does not lock data. Suggested: "A value that locks, unlocks, signs, or checks data. A shared key and a private key are secret. A public key is not."
- `quantum-computer`: "...break some of today's locks, such as X25519." The course uses "lock" for AES. X25519 is a key exchange, not a lock. Suggested: "...break some of today's key exchanges and signatures, such as X25519."

Two new glossary terms the step will need: `symmetric` ("One shared key locks and unlocks the data. Both sides hold a copy.") and `asymmetric` ("A key pair: a private key that stays with its owner, and a public key that anyone may have."). Also `public-key` and `private-key` if Richard uses them as `{{term:}}` links.

## 4. Where the step fits

### In lesson 1

- **Best place: L1-S02 "Both sides hold the same key".** The secrets panel shows one key in two lanes at this moment. Add the name "symmetric" here. Then add two short sentences: the hard part is getting that one key to both sides in public; a second kind of key, a key pair, solves it, and lessons 3 and 4 show how. Do not explain the math here.
- **Second touch: L1-S08 "GCM catches edits".** Add one sentence: the tag shows that someone with the shared key made the message, and both sides hold that key. Lesson 4 shows a signature, which points at one owner.
- **Third touch: L1-S11 "What to take away".** One line: lesson 1 is the symmetric lock that carries the data; the asymmetric parts in lessons 3 and 4 set up its key.
- Keep L1-S01 short. It already has four terms. Adding two more there makes the first step heavier, which is the "mud" Steve named.

### Pointers back from later lessons

- **Lesson 3, L3-S01: yes.** It already says "Lesson 1 locked data with a shared key." Change it to name the word: "Lesson 1 locked data with a symmetric key: one key, shared by both sides." Then name the key pair as asymmetric in L3-S02, where the private number and the public share appear.
- **Lesson 4, L4-S01 or L4-S09: yes.** A signature is the asymmetric partner of the lesson 1 tag. One sentence in L4-S09: "A tag from lesson 1 needs a shared key, so either side could make it. A signature needs the private key, so only its owner can make it."
- **Lesson 5, L5-S01: optional.** It already maps the three jobs to lessons 3, 4, and 1. One phrase makes it complete: "the asymmetric parts set up the key, then the symmetric lock carries the data."
- **Lesson 7, L7-S05: optional.** It is the one true public-key encryption in the course. A pointer to the lesson 1 step fits there.

## 5. AES step by step, and keys in depth (added 2026-11-06)

Sources: FIPS 197 (2023 update), read from the NIST PDF this session. `src/NetSec.Core/Crypto/AesKey.cs`, `Gcm.cs`, `Modes.cs` at origin/main `7b569a1`.

**Two changes I would make first**

1. Walk one AES block once, and label what goes in. The input is a counter in GCM, letters XOR the last cipher block in CBC, and letters only in ECB.
2. Show GCM as: AES locks a counter, then XOR makes the text. GCM decryption runs AES **forward**. It never runs the inverse steps.

### 5.1 The AES steps

The block is always 16 bytes. The key size changes the number of rounds, and the block stays 16 bytes (FIPS 197 Table 3; `AesKey.cs:45`).

| Key | Rounds | Round keys |
|---|---|---|
| AES-128 (16 bytes, lesson 1) | 10 | 11 |
| AES-192 (24 bytes) | 12 | 13 |
| AES-256 (32 bytes) | 14 | 15 |

The grid: 16 bytes fill a 4 by 4 grid **column by column**, top to bottom. Bytes 0 to 3 are the first column. A grid drawn row by row gives the wrong ShiftRows picture.

Before the first step, KeyExpansion stretches the key into the round keys. AES-128 makes 176 bytes of round keys from 16 bytes of key (`AesKey.cs:129`).

| Step | What it does, in eighth-grade words | Uses the key? |
|---|---|---|
| AddRoundKey | XOR each byte with the matching byte of this round's key. | **Yes. It is the only step that does.** |
| SubBytes | Swap each byte for another byte, using one fixed table of 256 entries (the S-box). The table is public. It is the same for every key. | No |
| ShiftRows | Slide each row to the left. Row 0 stays. Row 1 moves 1 place, row 2 moves 2, row 3 moves 3. Bytes wrap around. | No |
| MixColumns | Mix the 4 bytes of each column, so each new byte depends on all 4 old bytes. It uses a special multiply, and ordinary arithmetic gives the wrong answer. | No |

**Encryption order** (FIPS 197 Algorithm 1; `AesKey.cs:57-65`):

1. AddRoundKey with round key 0.
2. Rounds 1 to 9 (AES-128): SubBytes, ShiftRows, MixColumns, AddRoundKey.
3. Round 10: SubBytes, ShiftRows, AddRoundKey. The last round skips MixColumns.

**Decryption order** (FIPS 197 INVCIPHER, section 5.3; `AesKey.cs:78-86`). It uses the same key, and it uses the round keys from last to first.

1. AddRoundKey with round key 10.
2. Rounds 9 down to 1: InvShiftRows, InvSubBytes, **AddRoundKey, then InvMixColumns**.
3. Last: InvShiftRows, InvSubBytes, AddRoundKey with round key 0.

| Inverse step | What it does |
|---|---|
| InvShiftRows | Slides each row to the **right** by 0, 1, 2, 3 places. |
| InvSubBytes | Uses the reverse table, so each byte swaps back. |
| InvMixColumns | Unmixes each column. It uses larger multipliers (14, 11, 13, 9) where MixColumns uses 2, 3, 1, 1 (`AesKey.cs:121`). |
| AddRoundKey | Is its own inverse. XOR with the same bytes twice gives the first value back. |

Why AddRoundKey comes before InvMixColumns: each encryption round ends with MixColumns, then AddRoundKey. To undo that, take off the last thing first. I tested the other order with the plain round keys. It returns junk (`70 a4 c2 2d ...`). The order with InvMixColumns before AddRoundKey is correct only in FIPS 197 EQINVCIPHER (section 5.3.5), which needs a changed key schedule. The course does not use it. A source that lists the inverse steps in that order is describing something else.

Two code facts for the walk:

- `SubstituteAndMove` does SubBytes and ShiftRows in one pass (`AesKey.cs:98`). The order of the two makes no difference to the result (S-box works per byte, ShiftRows only moves bytes; I checked 240 states). A lesson may show them as two steps, as FIPS 197 does. The engine has no value between them today, so a panel must compute that value itself.
- `AesKey` exposes no round states. It returns only the final 16 bytes. A panel that shows rounds needs its own code or a new read path. Check its last value against `EncryptBlock`.

What each step gives, measured: flip one input bit, and 4 bytes differ after round 1. All 16 bytes differ after round 2. In this one test, 54 of the 128 output bits changed. A lesson can say "about half the bits change" and show this count.

### 5.2 What GCM changes

**State this in the lesson: inside GCM, AES never sees the message.** AES locks a counter block. XOR with that result makes the text. A walk that shows SubBytes on the message letters inside GCM is false.

Lock (`Gcm.cs:25-26`, `CounterCrypt`):

1. Build a counter block: the 12-byte nonce, then a 4-byte count. The count starts at 2 for the data (`Gcm.cs:92`). Count 1 is kept for the tag.
2. Run the counter block through AES **forward**, all 10 rounds. The result is 16 bytes of key stream.
3. XOR the key stream with 16 bytes of message. That is the ciphertext.
4. Add 1 to the count. Repeat for the next block.
5. Make the tag over the ciphertext.

Unlock (`Gcm.cs:40-44`):

1. Check the tag first. On a bad tag, return nothing.
2. Build the same counter blocks. Run them through AES **forward**, the same as locking. This gives the same key stream.
3. XOR the key stream with the ciphertext. The letters come back, because XOR twice undoes itself.

`Gcm.cs` never calls `DecryptBlock`. InvSubBytes, InvShiftRows and InvMixColumns do not run in GCM.

The tag: GHASH is a multiply in a different field (`Gcm.cs:67`). It is not AES. AES takes part twice: AES of a zero block makes the hash key (`Gcm.cs:51`), and AES of the first counter makes a mask that XORs onto the result (`Gcm.cs:55`).

The count for one message: the 64-byte text makes **6 forward AES calls** on each side (1 hash key, 1 tag mask, 4 counters) and 0 inverse calls.

| Mode | What goes into AES when locking | Inverse AES when unlocking? | Code |
|---|---|---|---|
| ECB | The data block | Yes | `Modes.cs:17`, `Lesson01Aes.cs:212` |
| CBC | The data block XOR the last cipher block (the IV at the start) | Yes, then XOR | `Modes.cs:30`, `Modes.cs:43` |
| GCM | A counter block | **No, forward only** | `Gcm.cs:97` |
| CTR, SSH modern suite (lesson 8) | A counter block | **No, forward only** | `SshPackets.cs:32` |
| CMAC (lesson 2) | Used to make a seal, with no unlock | **No, forward only** | `Cmac.cs:31,40,50` |

Inverse AES runs in the course in lesson 1 (ECB and CBC), lesson 6 (the bank opens the PIN block, `PinBlock.cs:80,83`), lesson 7 (CBC records, `Tls11Records.cs:63`), and the lesson 8 old suite (`SshPackets.cs:74`). Lesson 5 (TLS 1.3 GCM) uses only forward AES.

**The ECB trap.** Even in ECB, the first SubBytes sees letters XOR round key 0. So "SubBytes on the plaintext" is loose for every mode. In lesson 1, the text goes through ECB only on the `L1-use-ecb` attack run. The default run sends only the picture through ECB. A walk of "Pump four is ok." therefore needs a label, such as "a teaching example" or "the ECB attack run".

### 5.3 Checked example bytes for the walk

These are fixed teaching values. They are neither the lab's random key nor a lab run. The key is `000102030405060708090a0b0c0d0e0f` (the FIPS 197 C.1 key). Its first byte is 00, so the first letter looks unchanged after round key 0. That is a chance effect, and the other bytes do change.

AES on the block "Pump four is ok." (`50756d7020666f7572206973206f6b2e`), as in ECB:

| Point | State |
|---|---|
| After AddRoundKey 0 | `50746f73246369727a2963782c626521` |
| Round 1 SubBytes | `5392a88f36fbf940daa5fbbc71aa4dfd` |
| Round 1 ShiftRows | `53fbfbfd36a54d8fdaaaa8407192f9bc` |
| Round 1 MixColumns | `b65559145a3f83b7a236fbf70ae2d59b` |
| Round 1 AddRoundKey | `60ff2de98890f14d78908306dc49a365` |
| Output after round 10 | `1610a123c9fcfa091657149ba001aedb` |

GCM on the same letters, nonce `a0a1a2a3a4a5a6a7a8a9aaab`:

| Point | Bytes |
|---|---|
| Counter block | `a0a1a2a3a4a5a6a7a8a9aaab00000002` |
| AES forward gives key stream | `aa8638bb7e89330a8a78b5004612b060` |
| XOR with the letters gives ciphertext | `faf355cb5eef5c7ff858dc73667ddb4e` |

Four equal text blocks give four different cipher blocks, because the count changes.

Round 1 of FIPS 197 Appendix B, for a walk that cites the standard: start `193de3bea0f4e22b9ac68d2ae9f84808`, SubBytes `d42711aee0bf98f1b8b45de51e415230`, ShiftRows `d4bf5d30e0b452aeb84111f11e2798e5`, MixColumns `046681e5e0cb199a48f8d37a2806264c`, round key `a0fafe1788542cb123a339392a6c7605`, end `a49c7ff2689f352b6b5bea43026a5049`. Output `3925841d02dc09fbdc118597196a0b32`.

How these were checked:

1. An independent Python AES, written from FIPS 197, shares no code with the course. It gives the three FIPS 197 C.1 to C.3 answers and the Appendix B round 1 values.
2. The course's own `AesKey.cs` and `Gcm.cs`, built from origin/main in a scratch folder, give the same ECB output and the same 64-byte GCM ciphertext as the Python.
3. The round values come from the Python. `AesKey` exposes no round states, so only its final output is compared.

### 5.4 Symmetric and asymmetric, by lesson

| Lesson | Kind | What it uses |
|---|---|---|
| 0 | Neither | A pipe with no lock. |
| 1 | Symmetric | AES-128: ECB, CBC, GCM. |
| 2 | Symmetric | Seals with a shared key: HMAC, CMAC. A hash alone has no key. |
| 3 | Asymmetric | X25519 and ML-KEM-768 make a shared secret. |
| 4 | Asymmetric | Ed25519 signatures and certificates. |
| 5 | Both | TLS 1.3. Section 5.6 below. |
| 6 | Symmetric only | DUKPT. Every key comes from a base key by AES, and no key pair appears. |
| 7 | Both | TLS 1.1: RSA key transport, then AES-128-CBC with HMAC-SHA-1 (`Tls11Messages.cs:20`). |
| 8 | Both | SSH modern: curve25519, ssh-ed25519, aes128-ctr, hmac-sha2-256. Old: DH group 14, ssh-rsa, aes128-cbc, hmac-sha1 (`SshExchange.cs`). |
| 9 | Both | A DUKPT PIN block (symmetric) rides inside SSH and TLS. |
| 10 | Mostly asymmetric | Client certificates, a device key that signs a challenge, a token that a public key checks. All of it runs over TLS 1.3. |
| 11 | Neither | Timing of a compare. It uses no key pair and no lock. |

### 5.5 What each key can and cannot do

| Key | Can | Cannot |
|---|---|---|
| Shared AES key | Lock, unlock, seal, check. Fast, for any amount of data. | Show which side made a message. Reach the other side by itself. |
| X25519 pair | Agree on a secret with the other side's public share. | Sign. Lock a chosen message. Show who the other side is. |
| ML-KEM pair | The public key closes a box around a random value. The private key opens the box. Both sides hash that value into the shared key. | Carry a message that you choose (the engine draws the value at random, `KeyExchange.cs:110`). Sign. |
| Ed25519 pair | The private key signs. The public key checks. | Lock or unlock anything. Agree on a secret. |
| RSA pair | The public key locks a small secret, and the private key opens it. The private key also signs. | Lock bulk data. The block is at most the key size (256 bytes for 2048 bits, with some bytes used for padding). |

What a key pair can never do by itself:

1. **A public key alone names nobody.** Anyone can make a pair and claim a name. A certificate (lesson 4) or a stored host key (lesson 8) ties the key to a name.
2. **A box says nothing about the sender.** Anyone can lock a box with a public key. It shows who can open it, and nothing about who sent it.
3. **Key exchange alone is with "someone".** Both sides reach a shared secret, but with an unknown party. An attacker in the middle can run an exchange with each side. The signature stops this.
4. **The private key is the whole identity.** Whoever holds a copy can sign as the owner.

Other facts a lesson may use:

- Sharing keys does not scale for symmetric keys alone. 100 people need 4,950 shared keys, one per pair. With key pairs, each person publishes one public key.
- Key lengths do not compare across kinds. AES-128 is 16 bytes, X25519 is 32 bytes, RSA is 256 bytes or more. A longer number across kinds does not mean stronger.
- Both kinds have a place. "Asymmetric is newer or stronger" is false. They do different jobs.

### 5.6 How the two work together in TLS 1.3 (lesson 5)

1. **Asymmetric, key exchange.** The client sends a fresh X25519 public share and an ML-KEM public key. The server replies with its share and the ML-KEM box. Both sides compute one shared secret. The X25519 part never crosses the wire. The ML-KEM part crosses only inside its box, as a random value that both sides hash (section 5.10). The pairs are fresh for each connection (`KeyExchange.cs:31`).
2. **Key ladder (hashing).** HKDF turns that secret into four traffic secrets: client and server, handshake and application (`Tls13KeySchedule.cs:36-42`). Each traffic secret gives one AES key and one 12-byte IV (`:78`, `:83`).
3. **Symmetric starts.** From here, AES-GCM seals every handshake record.
4. **Asymmetric, identity.** Inside those sealed records, the certificate carries the CA's Ed25519 signature. CertificateVerify is the server's Ed25519 signature over the handshake so far. This shows the server holds the private key for that name.
5. **Symmetric, integrity.** Finished is an HMAC with a key from the ladder. It shows that neither side saw a changed handshake.
6. **Symmetric, data.** Real data goes in AES-GCM records.

Three ways TLS 1.3 differs from lesson 1. The walk must not blur them:

| | Lesson 1 | TLS 1.3 |
|---|---|---|
| Keys | One key for all messages | One key per direction. Both sides hold both keys, so it is still symmetric. |
| Nonce | Random, 12 bytes | IV XOR the record count (`Tls13Records.cs:63-68`) |
| Extra data (AAD) | Empty | The record header (`Tls13Records.cs:42`) |

Compare TLS 1.1 (lesson 7): the client locks the secret with the server's long-term RSA key. If that key leaks later, a recording of the old session can be opened. TLS 1.3 throws its exchange pairs away, so a later leak of the signing key does not open old recordings. SSH (lesson 8) follows the TLS 1.3 pattern, and a stored host key takes the place of the certificate authority.

### 5.7 Lines a lesson must not copy

Sources: the lead's example, and the Wikipedia AES page read today. The lines from Steve's paste are in section 5.11. Treat all of them as leads. FIPS 197 is the source.

| Do not copy | Right version |
|---|---|
| "SubBytes replaces each byte of the plaintext" | SubBytes works on the state. Even in ECB, the first SubBytes sees letters XOR round key 0. In GCM it sees a counter. |
| "Before round 0, the state array is simply the plaintext" (Wikipedia, SubBytes section) | True only in ECB, and only before the first AddRoundKey. The same page has no CTR or GCM content, so it covers only the block step. |
| "Decryption runs the same steps in reverse" | True for AES on one block. False for GCM and CTR, which run AES forward on both sides. |
| "Decryption undoes each step using the same key" (with no mode named) | Name the mode. GCM has no inverse steps. |
| "Inverse order: InvSubBytes, InvShiftRows, InvMixColumns, AddRoundKey" | That is EQINVCIPHER with a changed key schedule. The course uses section 5.3: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns. |
| "10 rounds of the same four steps" | 11 AddRoundKeys, and the last round has no MixColumns. |
| "The key is used in every step" | Only AddRoundKey uses it. |
| "The S-box is secret" | The S-box is public and fixed. Only the key is secret. |
| "AES-256 uses bigger blocks" | Every AES block is 16 bytes. A longer key adds rounds. |
| "Bytes fill the grid row by row" | Column by column. |
| "AES makes the GCM tag" | GHASH makes it. AES supplies the hash key and the mask. |
| "The private key decrypts, so signing is decrypting" | Ed25519 has no lock or unlock step. Keep "sign" and "lock" apart (section 3). |

### 5.8 The S-box

Sources: FIPS 197 sections 5.1.1 and 5.3.2, Tables 4 and 6. `AesKey.cs:169` (`BuildSbox`).

**Size.** The AES S-box takes 8 bits and gives 8 bits. It has 256 entries. AES uses one table for every byte, every round, and every key. The table is public.

**Row and column lookup.** Split the byte into two hex digits. The first digit picks the row. The second digit picks the column.

| Input | Row | Column | Output | Note |
|---|---|---|---|---|
| `53` | 5 | 3 | `ed` | The FIPS 197 example |
| `50` ("P") | 5 | 0 | `53` | Do not confuse this with the row above. `53` is an output here and an input there. |
| `00` | 0 | 0 | `63` | Zero does not stay zero. |
| `ff` | f | f | `16` | |

**How the table is built, in two stages** (FIPS 197 section 5.1.1):

1. Take the byte's multiplicative inverse in the AES field. "Inverse" means the value that gives 1 under the special multiply from MixColumns. The byte `00` has no inverse, so it stays `00`.
2. XOR that value with four rotated copies of itself and with `63`.

Worked example for `53`: the inverse is `ca`, because `53` times `ca` gives `01`. The rotations by 1, 2, 3 and 4 bits are `95`, `2b`, `56`, `ac`. `ca` XOR `95` XOR `2b` XOR `56` XOR `ac` XOR `63` = `ed`.

The code builds both tables at start-up from this rule, and has no stored list. It finds inverses with powers of 3 (`AesKey.cs:169`). The tables are private, so a panel needs its own copy or a new read path.

**The inverse table.** Swap inputs and outputs (FIPS 197 Table 6). Row e, column d gives `53`, which undoes `53` to `ed`. The S-box is not its own inverse, so decryption needs the second table.

**What the S-box adds to security:**

1. **It breaks straight-line math.** FIPS 197 calls SubBytes non-linear. The other three steps use only XOR and fixed moves. In my test, `S[x XOR y]` differs from `S[x] XOR S[y] XOR S[0]` in 64,260 of 65,536 pairs. A linear table would differ in 0.
2. **It hides patterns in the input.** Measured on the full table: for any fixed change to the input, a given output change appears for at most 4 of the 256 inputs. The best straight-line guess at a bit relation is off even odds by at most 16 of 128.
3. **It holds no secret, and it spreads nothing by itself.** One input byte changes one output byte. ShiftRows and MixColumns do the spreading. The key enters only through AddRoundKey.
4. **It also protects the key.** KeyExpansion uses the same table (`SubWord`, `AesKey.cs`).

Other checked facts:

- No byte maps to itself, and none maps to its bit-flipped opposite (checked over all 256). Inversion alone would leave `00` and `01` fixed. The second stage removes those.
- "Confusion" and "diffusion" are Shannon's words. FIPS 197 does not use them, and I have not read his paper this session. If a lesson uses them: confusion = the S-box's job, diffusion = the job of ShiftRows and MixColumns. Label that mapping as common teaching.
- A table lookup at a secret index can leak through a CPU cache. The `AesKey` comment says so, and production AES uses hardware instructions. This is a link to lesson 11.

**DES is different.** DES has eight S-boxes, and each turns 6 bits into 4, so it cannot be undone alone (`Des.cs:56`, `:152`). DES decryption reuses those S-boxes with the round keys reversed (`Des.cs:137`), so DES has no inverse table. `Des.cs` is in the repo, and my grep found no caller in `src/NetSec.Core` outside `Des.cs` and `TdesKey.cs`. No lesson needs this contrast.

### 5.9 Lines from Steve's GeeksforGeeks pages that a lesson must not copy

I read each page through a summary tool that quoted it, so the quotes may have small changes. They are leads. FIPS 197 and the engine are the sources. All four pages match the depth Steve wants, and these lines are the ones to avoid.

**`advanced-encryption-standard-aes`**

| Page says | Problem | Right version |
|---|---|---|
| "Each round comprises of 4 steps" | The page lists no AddRoundKey before round 1. | One AddRoundKey comes first. AES-128 has 11 AddRoundKeys. The last round has 3 steps (the page does say MixColumns is skipped there). |
| "The decryption process is the encryption process done in reverse" | True for one block only. | GCM and CTR run AES forward on both sides. |
| Decrypt stages: "Add round key", "Inverse MixColumns", "ShiftRows", "Inverse SubByte" | "ShiftRows" must be InvShiftRows, which slides right. The grouping starts differently from FIPS 197, and it holds only if the first decrypt round skips InvMixColumns. | Use the section 5.1 order, which is FIPS 197 section 5.3. |
| "developed by the National Institute of Standards and Technology (NIST) in 2001" | NIST selected Rijndael in 2000 and published the standard (FIPS 197). NIST was not the designer. | "NIST chose the Rijndael cipher and published it as AES." |
| "AES encryption is commonly employed to store passwords securely" | Anything encrypted can be decrypted by whoever holds the key. | Systems store a password as a slow, salted hash. The course has no password store. Leave this out. |
| "much stronger than DES ... despite being harder to implement" | I can support "stronger" (key size and block size). "Harder to implement" has no source. | Drop that clause. |
| "Each 128 blocks goes through" | A slip. | "Each 128-bit block". |
| "matrix multiplication" (MixColumns) | The numbers are right. The arithmetic is the special multiply, and ordinary multiply gives wrong bytes. | Name the special multiply. |

Correct on this page, so usable: rounds, grid by column, row shifts, both matrices, "never substituted by itself", no bit-flipped opposite. It covers no modes, so it says nothing about GCM.

**`what-is-s-box-substitution`**

| Page says | Problem | Right version |
|---|---|---|
| "a group of 4 bits", "each 4-bit chunk from your message" | False for AES, and the page's own table (`63 7C 77 ...`) is the 8-bit AES table. The 4 bits pick a row or a column. They are never swapped alone. | 8 bits in, 8 bits out. |
| "replace each possible 4-bit group with a different 4-bit group" | Same problem. The page is not describing DES either, which turns 6 bits into 4. | See section 5.8. |
| "Each byte of the plaintext undergoes substitution" | Same trap as section 5.2. | Each byte of the state. |
| "A symmetrical S-box is a ... near-inverse or near identity map" | The AES S-box is neither. It has no fixed points, and it is not its own inverse. | Leave this out. |
| S-boxes credited with "changing a single bit in plaintext results in changing numerous bits" | One changed byte stays one byte through the S-box. | MixColumns and ShiftRows spread it: 4 bytes after round 1, 16 after round 2. |
| "it improves security by apprehension at the expense of linearity effects" | It has no clear meaning. | Leave this out. |

The page gives no row and column rule and no build method. Use section 5.8.

**`what-is-a-symmetric-encryption`**

| Page says | Problem | Right version |
|---|---|---|
| "shared-key" or "private-key" encryption | In this course, "private key" is half of a key pair. | Use "shared key" only. |
| "A secure key is generated using algorithms like PBKDF2" | PBKDF2 stretches a password. The course has no PBKDF2 (grep: 0 hits). | Lesson 1 draws random bytes. TLS 1.3 derives keys with HKDF. |
| "This key must be securely shared or transferred over the network" | X25519 sends no key at all. DUKPT loads the starting key before the run. | The two sides must hold the same key. Sending it is one way of many, and lessons 3 and 6 show others. |
| "a reverse encryption algorithm" | False for GCM and CTR. | Name the mode. |
| "the complexity ... increases exponentially" | The growth is quadratic. | n people need n(n-1)/2 keys. 100 people need 4,950. |
| "Even if intercepted, it remains unreadable" (CBC example), with no mention of edits | Lesson 1 shows CBC has no check. Encryption gives no proof that nobody changed the data. The page also never mentions integrity. | Pair this with the lesson 1 flip test, and with GCM. |

**`what-is-asymmetric-encryption`**

| Page says | Problem | Right version |
|---|---|---|
| "If the receiver can successfully decrypt the message, it proves that the sender owns the corresponding private key" | **False. This is the worst line on the four pages.** Anyone can lock with a public key. Unlocking shows the receiver's key works, and nothing about the sender. | Only a signature points at the sender. |
| "A digital signature is created by encrypting a hash of the data with the sender's private key" | False for Ed25519, the course's signer. | The private key signs. The public key checks. |
| "the sender cannot deny sending" (as an advantage of asymmetric encryption) | Encryption does not give this. | A signature does, if the private key stayed private. |
| "provides a higher level of security compared to symmetric encryption" | They do different jobs. | See section 3. |
| "eliminates the need for a secure key distribution system" | The public key must still be the right one. An attacker can hand over a false one. | Lesson 4 (certificates) and lesson 8 (stored host keys). |
| "the Diffie-Hellman key exchange algorithm uses asymmetric encryption" | DH encrypts nothing. | It is asymmetric key agreement. |
| "The server sends its public key to the browser" (TLS) | TLS 1.3 has two separate keys here. Section 5.10 has them. | Fresh key share for the secret, certificate key for the signature. |
| "the server challenges the user, who then proves identity by responding with their private key" (SSH) | The private key never moves. And in lesson 8, the client signs data that includes the session id (`SshClientRules.cs:168`). The server sends no challenge. | The client signs, and the server checks. Lesson 10 is the one with a challenge. |
| "is not suitable for real-time communications or streaming data" | Real-time links use it at setup. The page itself says so for VPNs. | It is slow for bulk data. |
| Email and files "encrypted using the recipient's public key" | In common practice, the public key locks a fresh shared key, and that shared key locks the data. | Same pattern as the rest of this sheet. |
| "SSL/TLS" | SSL is retired. | The course shows TLS 1.3, and TLS 1.1 as legacy. |

Correct and usable: slow for bulk data, setup then symmetric data, private key kept secret, RSA and ECC exposed to a future quantum computer. Add that ML-KEM is asymmetric and is built to resist that (lesson 3).

### 5.10 What the engine does with a public key, and which picture fits

The lead's note says that TLS 1.3 key exchange agrees a key and encrypts nothing with a public key. **That holds for X25519. It does not hold for the ML-KEM half of the hybrid, which lesson 5 uses** (`Tls13Lab.cs:55`). `MlKem768.Encaps` calls `KPke.Encrypt(ek, m, r)` (`MlKem768.cs:72`). That is public-key encryption of a random 32-byte value, inside the KEM. The shared key comes from a hash of that value, `G(m || H(ek))`, and the value itself is not the shared key. No message and no record data ever goes through a public key.

| Where | Public key does | Picture to use | Picture to avoid |
|---|---|---|---|
| X25519 (lessons 3, 4, 5, 8, 10) | Mixes with the other side's private key. Encrypts nothing. | Two sides mix, and reach one secret. | Any lock or box. |
| ML-KEM (lessons 3, 5) | Closes a box around a random value. | Open box that anyone can close and only the client can open. Say that both sides then hash the contents into a key. L3-S06 and L3-S07 fit. | "The server sends its key in a box." "Locks the message." |
| Ed25519 and certificates (lessons 4, 5, 8, 10) | Checks signatures only. It cannot lock. | A check against a signature. | "The browser locks data with the server's certificate key." |
| RSA (lesson 7) | Locks one small secret (`Tls11Rules.cs:227`). The server opens it (`Tls11Rules.cs:334`). | Lock and box. L7-S05 fits. | Using this picture as the general story of TLS. |
| Record data (all lessons) | Nothing. AES-GCM or AES-CBC with a shared key does it. | Symmetric lock. | "Data locked with the public key." |

**A safe sentence for asymmetric in general:** "A key pair does one of three jobs: agree on a secret, check a signature, or close a box around a small secret. Only the shared key locks the data."

The textbook sentence "encrypt with the public key, decrypt with the private key" describes RSA in lesson 7, and the inside of ML-KEM. It describes nothing else in the course. If a lesson uses it, name RSA.

### 5.11 Steve's search summary, line by line

The lead relayed these lines from Steve's paste. The cybernews page itself (`https://cybernews.com/resources/what-is-aes-encryption/`) refused my fetch with HTTP 403, so I checked the lines and not the page.

| Line | Result | Use in a lesson |
|---|---|---|
| Key Expansion makes round keys | Correct | Use it. |
| The initial round combines "the plaintext block" with the first round key | **True only in ECB.** The step is right. The input is letters XOR the last cipher block in CBC, and a counter in GCM. | Say "the input block". |
| Main rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey | Correct order | Use it. |
| MixColumns is "matrix multiplication" | Loose | Say "a matrix with a special multiply". Ordinary multiply gives wrong bytes. |
| The final round omits MixColumns | Correct | Use it. |
| Rounds are 10/12/14 | Correct as totals. The main rounds are 9/11/13, and the final round is one more. | Do not write "10 main rounds, then a final round". |
| "The decryption process reverses the encryption steps in the opposite order, using the same symmetric key." | **True for one block only.** False for GCM and CTR, which run AES forward on both sides. The key is the same, and the round keys run from last to first. | Name the mode. Use the section 5.1 order. |
| Block size is fixed at 128 bits | Correct | Use it. |
| DES has a 56-bit key | Correct. An 8-byte DES key has parity bits that go unused (`Des.cs:117`). | Use it if a lesson needs DES. |

### 5.12 The modes as lesson 1 runs them

Sources: SP 800-38A and SP 800-38D, read from the NIST PDFs this session. `Lesson01Aes.cs`, `Modes.cs`, `Gcm.cs`, and the golden trace `acceptance/golden/net10/lab-01.ndjson`, all at origin/main `7b569a1`.

**Two changes I would make first**

1. Say which promise each mode makes. ECB and CBC hide data and catch no edits. GCM hides data and catches edits.
2. Say "IV" and "nonce" with their own rules. The CBC IV must be unpredictable. The GCM nonce must be unique. Neither one is secret.

| | ECB | CBC | GCM |
|---|---|---|---|
| Promise | Hides single blocks only | Hides data | Hides data and catches edits |
| What goes into AES | The padded data block | The padded data block XOR the last cipher block | A counter block |
| Starting value | None | 16-byte random IV, fresh per message (`Lesson01Aes.cs:103`, `:105`) | 12-byte random nonce, fresh per message (`:97`, `:106-107`) |
| Padding | Yes | Yes | None |
| Text bytes in and blocks | 64 in, 5 cipher blocks | 64 in, 5 cipher blocks | 64 in, 4 cipher blocks |
| Wire bytes for the text (with the 4-byte frame header) | 84 | 100 | 96 |
| Unlock uses | Inverse AES | Inverse AES, then XOR | Forward AES, then XOR |
| Check on unlock | None | None | Tag |
| Picture repeats (golden trace) | 249 of 257 blocks | 0 of 257 | 0 of 256 |
| Lock in parallel? | Yes | No | Yes |
| Unlock in parallel? | Yes | Yes | Yes |

The text in ECB runs only on the `L1-use-ecb` attack, in the slot of `TextCbc`. The 100 and 84 are computed from the layouts. The 96 is pinned by Nancy's spec. The parallel rows for ECB and CBC are from SP 800-38A sections 6.1 and 6.2, and my shuffled-order CBC decrypt confirms the CBC row. The GCM row is from its counter design, and the tag calculation itself runs in order.

**One bit flipped in cipher block 2 of the padded text** (my test):

| Mode | Plaintext blocks changed | What the receiver does in lesson 1 |
|---|---|---|
| ECB | Block 2 only, all junk | Takes it, with no error |
| CBC | Block 2 all junk. Block 3 has 1 byte changed, the matching bit flipped. Block 4 and later are correct. | Takes it, with no error |
| CBC, flip in the IV | Block 1 only, the matching bit flipped | Takes it, with no error |
| GCM | Without the tag, 1 byte changes. With the tag, nothing comes out. | Refuses it |

SP 800-38D Appendix A calls counter mode "malleable" for this reason, and says that is why GCM adds the tag.

**Padding** (`Lesson01Aes.cs` `Pad`, `Unpad`):

1. The engine adds n bytes, each of value n, to fill the block. 60 bytes gets 4 bytes of `04`.
2. It pads every message. A full last block gets one more whole block. The 64-byte text gets 16 bytes of `10`, which is hex for 16. That is why the text shows 5 blocks and not 4.
3. SP 800-38A Appendix A gives a different example, a 1 bit and then 0 bits, and it says "Other methods may be used". So the engine meets the document, and the engine's form does not come from it. Common books call the engine's form PKCS#7. I give that name from memory and have not read its source this session.
4. `Unpad` removes the padding when it reads as padding. Otherwise it keeps the bytes (`:226-232`). It raises no padding error, so this lesson has no padding-error attack.
5. GCM needs no padding. XOR uses only the key stream bytes it needs.

**IV and nonce:**

| Rule | CBC IV | GCM nonce |
|---|---|---|
| Name in the standard | IV | IV ("essentially a nonce", SP 800-38D section 5.2.1.1). The course says "nonce", and that is fine. |
| Secret? | No. "need not be secret" (SP 800-38A section 6.2) | No |
| Must be | **Unpredictable** before the plaintext is known (SP 800-38A Appendix C). "Unique" is too weak. | **Unique** under one key (SP 800-38D section 8). A predictable value is allowed. TLS 1.3 uses a record count. |
| Ways to get it | A random block, or AES of a unique value under the same key | A random 96-bit value, capped at 2^32 uses per key (sections 8.2.2, 8.3), or a built value (8.2.1) |
| Travels with the message? | Yes, in lesson 1 | Yes, in lesson 1. In TLS 1.3 it never travels, and each side computes it. |
| If it repeats | Same first blocks show as same cipher blocks (my test) | The XOR of two ciphertexts gives the XOR of the two plaintexts (my test). The hash key can leak, and then an attacker can forge tags (SP 800-38D Appendix A). |

Lesson 1 sends 3 GCM messages under one key, so the 2^32 cap has no effect on it. The lab draws from `c.Random`. The golden runs repeat byte for byte, so the source there is repeatable. Do not describe it as an approved random generator.

Glossary check: the `iv`, `nonce`, `ecb`, `cbc` and `gcm` entries are all correct at beginner level. The `block` entry is still loose for GCM (section 2).

How this was checked:

1. Independent Python gives the SP 800-38A F.1.1 and F.2.1 ciphertexts for ECB and CBC.
2. Independent Python GCM, with GHASH written from SP 800-38D algorithm 1, gives the course `Gcm.cs` tag `ced9be742e604bd3c021c4aca8730192` for the section 5.3 example.
3. The repeat counts come from the committed golden trace. I did not run the lab.

### 5.13 Lines from the GeeksforGeeks modes page

`block-cipher-modes-of-operation`, read through a summary tool that quoted it, so the quotes may have small changes.

**False or misleading:**

| Page says | Problem | Right version |
|---|---|---|
| CBC: "A corrupted ciphertext block affects subsequent blocks" | **False as worded.** It reads as if the damage runs on. Only the next block changes (table in section 5.12). | One block turns to junk, and the next block has the same bit flipped. Then it recovers. |
| CBC: "Requires a unique IV" | **Too weak.** SP 800-38A requires unpredictable. | Unpredictable, and CFB too. |
| IV: "ensures they are unique and unpredictable" (as a rule for all modes) | **Too strong for counter-style modes.** GCM and OFB need unique only. A predictable TLS 1.3 count is correct. | Give the rule per mode. |
| IV: "a random or unique value" (as one rule) | The rule differs per mode. | Same. |
| IV: "IVs should be transmitted or stored alongside the ciphertext" | True in lesson 1. False for TLS 1.3, where each side computes it. | "The receiver must have it. Many systems send it." |
| OFB alone has "Does not provide authentication" | The page implies the others do. ECB, CBC, CFB, OFB and CTR all give none (SP 800-38A calls them confidentiality modes). | Only GCM on this page's list catches edits. |
| ECB: "Vulnerable to cryptanalysis" | AES is fine, and no analysis is needed. Equal blocks show by looking. | "Shows patterns." SP 800-38A says not to use ECB if this property is undesirable. |
| ECB: "Suitable only for encrypting very small and independent data blocks" | Not from SP 800-38A. "Small" does not make it safe: two equal small messages still look equal. | Leave this out. |

**Gaps a lesson must fill. The page does not state these:**

- Padding for ECB and CBC. It mentions padding only to say CFB does not need it.
- Decryption for ECB, CBC, OFB and CTR. CBC decryption can run in parallel, and the page does not say so.
- GCM, which is one mention only. Use sections 5.2 and 5.12.

**Correct and usable:** equal ECB blocks give equal cipher blocks, ECB parallel both ways, the CBC chain and first-block IV, CBC encrypt is not parallel, CFB and OFB and CTR need no padding and use forward AES, CTR counters never repeat under one key, and OFB with a repeated IV loses security.

CFB, OFB and XTS appear on the page, but lesson 1 does not run them, so leave them out. CTR runs in the SSH modern suite (lesson 8).

### 5.14 The full cybernews page, as the lead relayed it

Steve pasted the page to the lead, and the lead sent me these claims. I did not see the paste itself, so this checks the claims as relayed. FIPS 197 and my own code are the sources.

| # | Page says | Result | Evidence and right version |
|---|---|---|---|
| 1 | S-box: `e9` becomes `1a` | **False.** | `e9` gives `1e` (Table 4, and FIPS 197 Appendix B round 1). `1a` is the output for input `43`. |
| 1b | S-box: `19` becomes `d4` | Correct | Table 4, Appendix B. |
| 2 | 256-bit key count, a 36-digit figure ending `...639,936` | **False.** | 2^256 has 78 digits, about 1.16 x 10^77. The figure looks like the last 36 digits of the true number, with the front cut off. The page's own 1.1 x 10^77 is close. |
| 3 | Cryptographers improved the AES key schedule after the 2009 related-key attacks | **False.** | FIPS 197-upd1 Appendix D (2023) kept "the technical specifications". My Python gives the 2001 appendix C values and the 2023 Appendix A and B values from one key expansion. The date of the attacks is from memory. |
| 4 | The first AddRoundKey is the first round | **False, and it breaks the count.** | FIPS 197 calls it "an initial round key addition" before the Nr rounds. AES-128 has 10 rounds and 11 AddRoundKeys. |
| 5 | AddRoundKey "adds", and never says XOR | **Misleading.** | FIPS 197 addition in this field is XOR. Ordinary adding gives wrong bytes: `53` XOR `53` is `00`, and `53` + `53` is `a6`. Only XOR undoes itself. Say XOR. |
| 6 | The key schedule encrypts each symbol | **False.** | KeyExpansion makes round keys from the key. It uses rotate, S-box and a round constant on words. It never touches the data. |
| 7 | The last round skips MixColumns because of "too much processing power" | **Unsupported, and the sum is against it.** | FIPS 197 says only that it is omitted. MixColumns already runs 9 times in AES-128, so 1 more is no large cost. The designers' reason is in their proposal, which I have not read this session. Say "the last round has no MixColumns", and give no reason. |
| 8 | Decryption begins with "the inverse round key" | **False.** | It begins with AddRoundKey using the **last** round key (FIPS 197 INVCIPHER, line 3). AddRoundKey is its own inverse (section 5.3.4). No inverse key exists. |
| 9a | SSL is a type of encryption | **False.** | SSL is a retired protocol. It uses encryption. |
| 9b | Proper AES can help detect side-channel leaks | **False.** | A cipher detects nothing. Table AES can itself leak through a CPU cache (`AesKey.cs:8`). Lesson 11 measures a timing leak by test. |
| 10 | DES in 362 seconds, AES-128 in 36 quadrillion years | **Unsourced. No lesson uses them.** | They also disagree: at the rate 362 seconds implies, all of AES-128 takes about 54 quadrillion years, and half of it about 27. |
| 11 | No mode named, so the walk reads as if your text always goes through the rounds | **Misleading.** | True in ECB only. In GCM a counter goes through (section 5.2). |

**Confirmed correct:**

- Rounds are 9, 11, 13 main rounds, plus one last round (FIPS 197 Table 3).
- ShiftRows offsets are 0, 1, 2, 3 to the left.
- Key counts: 2^128 is about 3.4 x 10^38, 2^192 about 6.3 x 10^57, 2^256 about 1.16 x 10^77 (computed).

### 5.15 DUKPT, for lesson 6

**Conclusion.** Lesson 6 runs AES DUKPT, ANSI X9.24-3-2017. It does not run the older TDES form. AES-128 base key, AES-128 PIN key (`Lesson06Dukpt.cs:49-50`, `DukptDerivation.cs:30-31`).

| Fact | Older TDES form | This engine (AES) | Evidence for the engine |
|---|---|---|---|
| Future-key registers | 21 | 32 | `DukptPinPad.cs:30`. X9 Python reference: `NUMREG = 32` |
| KSN | 10 bytes (80 bits) | 12 bytes: 8-byte initial key id, 4-byte counter | `DukptDerivation.cs:30-31`, moov-io, X9 vectors |
| Counter | 21 bits | 32 bits | Same |
| One-bit limit on a counter | 10 (from memory) | 16 | `DukptPinPad.cs:33`. X9 Python reference: `MAX_WORK = 16` |
| First key's name | IPEK | Initial Key | Wikipedia note, X9 vectors |

**Free sources.** X9 publishes a free supplement to X9.24-3-2017: a test vector PDF and Python source. The standard itself is paid, and I have not read it. The vector PDF is `x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Test-Vectors-20180129-1.pdf`, SHA-256 `ae9bb01d...`, and the repo already fetches it (`acceptance/vectors/fetch-x9.ps1`). The lead's memory was right.

**Lines not to copy, Wikipedia (`Derived_unique_key_per_transaction`):**

| Page says | Result | Right version |
|---|---|---|
| "future and past transaction data are still protected" if a derived key is compromised | **False for a stolen reader.** I tested the engine: after 3 sales, the registers rebuild counters 4, 5, 8, 1,000 and 65,536, each equal to the real key. They rebuild counters 1, 2 and 3 for no one. | One leaked PIN key exposes one sale. Stolen registers expose all **future** sales, and no past sale. |
| "In X9.24-1:2017 (DUKPT based on AES)" | Conflicts with the page itself and with X9's supplement, which both name X9.24-3-2017 for AES. | AES DUKPT is X9.24-3. |
| KSN 80 bits, 21-bit counter, 21 registers, "over 1 million" operations | True for the TDES form the page describes. **False for lesson 6.** | The table above. |
| "IPEK" | The TDES name. | "Initial key" in lesson 6. |

**Lines not to copy, Futurex blog:**

| Page says | Result | Right version |
|---|---|---|
| "the current encryption key to form the key for the next transaction" | **False.** Counter 2's key comes from a register filled at load, and counter 1 fills nothing. | A register holds a derivation key. Using it fills the lower registers first, when any exist. |
| "ensuring that compromise of one key does not affect other transactions" | True for one working key. False for the registers (above). | Say which key. |
| The counter is "encrypted with the BDK, resulting in the injection" of the initial key | Loose. | The initial key is derived from the base key and the initial key id. |
| 10-byte KSN, 21-bit counter, "Triple DES" | TDES form only, with no AES mention. | The table above. |
| "ANS X9.24-1:2017" for more detail on DUKPT | Same conflict as Wikipedia. | X9.24-3. |

**A worked page: Arthur van der Merwe, "DUKPT Explained with Examples" (2015).** It covers the **TDES form**, ANS X9.24-2004 Annex A. I read it through a summary tool. I tried its example on BDK `0123456789ABCDEFFEDCBA9876543210`, KSN `FFFF9876543210E00008`.

| Value | Page | My code from its pseudocode, on .NET DES | moov-io `pkg/des`, commit `06e6668` |
|---|---|---|---|
| IPEK | `6AC292FAA1315B4D858AB3A3D7D5933A` | Match | Match |
| Key for counter 8 | Not listed | `27F66D5244FF62E1AA6F6120EDEB4280` | Same |
| "Session key" | `27F66D5244FF621EAA6F6120EDEB427F` | Match, and it equals the key XOR the **PIN** mask | Not exposed |
| Track data, CBC, zero IV | `%B5452300551227189^HOGAN/PAUL ...` | Match under that key | `DecryptData` gives junk, as expected: it uses the data key |

**Does not carry over to AES DUKPT:** the XOR variant masks (`C0C0...`, the PIN and data masks), the non-reversible key step, the 21-bit counter, the 10-byte KSN, the name IPEK. AES DUKPT builds each key by AES over derivation data that holds a usage code.

**Carries over:** base key to initial key, a walk over the counter's 1 bits, a last step to a working key, and a bank that needs only the base key and the KSN.

**Lines not to copy:**

| Page says | Result | Right version |
|---|---|---|
| The "session key" decrypts the track data | **Works, and it is a bad habit.** That key is the PIN variant, so the example uses a PIN key on card data. | One key per use. X9's AES vectors give separate PIN, MAC and data keys |
| "The BDK encrypts the KSN; the ciphertext is the IPEK" | Too short, for TDES and AES. In TDES, two halves come from the masked KSN, the second under a masked BDK. | "The bank derives it from the base key and the key id" |
| "PekMask `FF00000000000000FF`" (reader comment) | 9 bytes as printed, with the leading zeros missing. The mask that matches is `00000000000000FF00000000000000FF`. | Do not quote it |

**An open point on the counter limit.** The X9 Python reference and the engine differ at one edge. The reference updates at `oneBits <= 16`, so my model of it issues `0x1FFFF` (17 one bits) at sale 131,071. The engine and moov-io stop at 16 and skip to `0x20000`. The paid standard text decides this, and I have not read it. No lesson reaches this counter. The conformance matrix lists it as a gap.

### 5.16 AES defaults and code in the wild

| Claim | Result | Evidence |
|---|---|---|
| `.NET Aes.Create()` defaults | CBC, PKCS7, 256-bit key, 128-bit block | Run on .NET 10.0.14 |
| A flipped bit under those defaults, 64-byte text with a 16-byte padding block | Earlier blocks: no error on 384 of 384. Second-last block: padding error on 128 of 128. Last byte of the last block: padding error on all 8 bits | Same run. A real library can raise a padding error where lesson 1's lab raises none (`Unpad`). So keep "passes with no error" tied to the lab or to the earlier blocks. A 41-byte text, which ends part way through a block, differs: last block 128 of 128, second-last block only 56 of 128, first block 0 of 128. So a library "can" raise this error near the end. It does not always |
| MySQL `AES_ENCRYPT` default | `aes-128-ecb`, no IV | MySQL 8.4 reference: "Its default value is `aes-128-ecb`". The same page says to hash a password before passing it as the key |
| "ECB, often as a tool's default" | **Too strong.** MySQL's default is ECB, and .NET's is CBC. That is 1 of the 2 I checked | Use "ECB, the default in some tools" |
| Milan Jovanovic blog | No mode set, so CBC. IV in front. No tag. The real line says "the strongest security currently available in the AES standard" | Read through a summary tool. The key size says nothing about edits: a 256-bit key still passed the flip above |
| C# Corner, "AES in C#" | Confirmed. The SQL joins `textBox1.Text` into the query string beside the fixed key `'camellabs.com'`, which is the SQL injection shape. It also hard-codes user `root` and password `"password"`. No mode is set, so it runs AES-128-ECB under MySQL's default, unless the server changes that setting. It also says "the private key" for a shared key | Read through a summary tool. Nothing ran. No lesson names this page |
| SergeyBel/AES README (MIT) | First example is `EncryptECB`, and it carries no warning | Read |
| abdouskamel/aes-csharp `example/streamcipher.cs` (no licence stated) | ECB shape: each 16-byte read goes straight through the cipher, with no IV, nonce or tag. It fills a short block with zeros and never removes them | Read in full |

### 5.17 Key schedule, the field, and why each step exists

Sources: FIPS 197-upd1, Shannon 1949, read this session. Checks ran on my own AES, not on the lead's script.

| Fact | Result | Source |
|---|---|---|
| Key words 4, 6, 8. Rounds 10, 12, 14. Round keys 11, 13, 15. Words 44, 52, 60 | Holds | Table 3, section 5.2 |
| The first Nk words are the key. Each later word uses the word before it and the word Nk back | Holds | Section 5.2 |
| w3 `09cf4f3c`, RotWord `cf4f3c09`, SubWord `8a84eb01`, after Rcon `8b84eb01`, w4 `a0fafe17` | Holds | Appendix A.1, row 4 |
| All words for the three key sizes | My expansion's 40, 46 and 52 words all appear in Appendix A | Appendix A, my run |
| AES-256 uses SubWord alone at `i mod 8 = 4` | Holds. The standard says "if i + 4 is a multiple of 8" | Section 5.2 |
| Rcon `01 02 04 08 10 20 40 80 1b 36`, each from XTIMES | Holds. Field `80` doubled is `1b`, and ordinary doubling is `100` | Table 5, section 5.2 |
| One AES-128 round key gives back the key | Holds: 11 of 11 round keys in my run | Algorithm 2 run backward. FIPS 197 does not state this |
| The same line for AES-192 or AES-256 | **Does not hold.** One round key is 4 words, and running backward needs 6 or 8 | Same |
| Add is XOR | Holds | Section 4.1 |
| Multiply: polynomials, coefficients mod 2, reduced by `x^8 + x^4 + x^3 + x + 1` | Holds. FIPS writes the value as `{01}{1b}`, and `11b` is the same number | Section 4.2 |
| Each nonzero byte has one inverse | Holds: 255 of 255 | Section 4.4 |
| What a field is | FIPS 197 does not define it. It uses the term and sends the reader to textbooks (section 4, footnote 1) | Not in FIPS |
| `2 x d4 = b3`, `3 x bf = da`, ordinary `1a8` and `23d`, XOR gives `04` | Holds | Section 4.3 matrix, my run |
| Column `d4 bf 5d 30` gives `04 66 81 e5` | Holds | Appendix B, round 1 |
| No S-box fixed point, and no bit-flipped opposite | Holds: 0 and 0 of 256. FIPS 197 does not state this | Table 4, my run |
| Without ShiftRows, changed bytes per round stay at 4 | Holds in my test: 4, 4, 4, 4 | My run |
| Without MixColumns, they stay at 1 | Holds in my test: 1, 1, 1, 1. With both steps: 4, 16, 16, 16 | My run |

**The byte spread holds for every input bit.** Over 300 random keys and blocks at all three key sizes, each of 128 input bits: 4 bytes changed after round 1 in 38,400 of 38,400 cases, and 16 after round 2 in 38,400 of 38,400. The reason is structural: MixColumns has no zero factor and an invertible matrix, so one changed byte in a column changes all four, and ShiftRows then gives each column one changed byte. Output bits changed: 64 of 128 on average, 45 to 81, in 5,120 samples.

**Shannon's words.** C. E. Shannon, "Communication Theory of Secrecy Systems", Bell System Technical Journal, 1949, section 23. I read a retyped copy, and the text extraction drops the letters for message, cryptogram and key.

- Diffusion: "the statistical structure of [the message] which leads to its redundancy is 'dissipated' into long range statistics".
- Confusion: "to make the relation between the simple statistics of [the cryptogram] and the simple description of [the key] a very complex and involved one".

So "one changed bit changes about half the output" is the later word avalanche, not Shannon's definition. "Each output bit depends on many key bits" is not his wording either. Tying SubBytes to confusion, and ShiftRows and MixColumns to diffusion, is common teaching. Neither Shannon nor FIPS 197 makes that mapping.

### 5.18 GCM's field, and Computerphile's AES-GCM video

**Video:** `youtube.com/watch?v=-fpVv_T4xwA`. I read the lead's transcript with repeats removed, not the video. The transcript spells some words by ear. Leads only. Sources: SP 800-38D, RFC 8446, `Gcm.cs`.

| Time | Video says | Result | Source |
|---|---|---|---|
| @06:32 | H is AES of 128 zero bits | Correct | 38D section 5.3 ("zero" block), `Gcm.cs:51` |
| @07:30, @10:07 | Tag is the hash XOR AES of the first counter | Correct | 38D algorithm 4, `Gcm.cs:50-57`. My independent Python matches the course tag |
| @08:02, @08:19 | Multiply in a Galois field, as polynomials, then reduce | Correct | 38D section 6.3 ("binary Galois (i.e., finite) field"). 38D does not print the name GF(2^128). The size follows from its 128-bit blocks |
| @13:56 | A repeated nonce lets you find H by root finding, then forge | Correct, with a limit. 38D Appendix A says "likely". It needs two **different** messages | 38D Appendix A, and my test below |
| @11:20 | Check the tag before returning data | Correct as the rule. 38D lists the tag step last and allows either order | 38D section 7.2 |
| @16:58 | TLS 1.3 offers only 2 AEAD ciphers | **False.** RFC 8446 Appendix B.4 lists 5 suites: 2 AES-GCM, ChaCha20-Poly1305, 2 AES-CCM. All 5 are AEAD, which part of the line gets right. The course offers the 2 AES-GCM suites | RFC 8446 B.4, `Tls13Suite.cs:21-22` |
| @01:33, @03:06 | The nonce is random, so you cannot predict it | **Misleading.** The need is that it never repeats under one key. 38D allows a built value, and TLS 1.3 uses a record count | 38D section 8, `Tls13Records.cs` |
| @01:00 | Anything not 128 bits must be padded | **False for counter mode and GCM.** They XOR only the bytes needed | `Gcm.cs:97-99` |
| @01:53 | Counters run n+0, n+1, n+2 | Loose. In GCM with a 96-bit nonce, the mask uses count 1, and data starts at count 2 | 38D section 7.1, `Gcm.cs:92`, `:108` |
| @05:59, @11:04 | The nonce is authenticated in the hash | Loose. GHASH covers the AAD, the ciphertext and both lengths, not a 96-bit nonce. A changed nonce still fails, because the mask changes. The tag check runs first, so the key stream plays no part in the failure | 38D section 7.1, my flip run in the #146 review |
| @17:17 | Tags are often cut to 96 bits | Allowed by 38D (128, 120, 112, 104, 96). TLS 1.3 GCM uses 16 bytes, and this course always does | 38D section 5.2.1.2 |

**H from a repeated nonce, tested on paper in my scratch folder.**

- **Lesson 1's reuse run cannot show it.** `L1-reuse-nonce` sends the same text twice (`Lesson01Aes.cs:102`, `:107`). So the ciphertext and tag are the same, and both XORs are zero.
- **Two messages that differ only in the last block give H directly, with no root finding.** Then `T xor T'` equals `(C xor C') x H^2`, and squaring undoes in this field. My run recovered `c6a13b37...d879`, equal to AES of the zero block, from public bytes alone. A tag forged with it equalled the key holder's tag. Two different nonces gave a wrong value, as they should.

## Disposition

Lesson 1 engine facts and claims L1-C01 to L1-C05 match the code. The current tour text has no false statement. The gaps are a missing name (symmetric), the tag-versus-signature line, and the `key` glossary entry. I review Richard's PR and Nancy's PR on request.

Section 5: AES steps match FIPS 197 and `AesKey.cs`. GCM facts match `Gcm.cs`. Tier: test against an independent implementation, on origin/main `7b569a1`. Anchor: FIPS 197 known answers. Not checked: Steve's paste, and the cybernews page. Round states are checked against the Python and FIPS 197 only, because `AesKey` exposes none. Recommendation: Richard writes the walk from sections 5.1 to 5.3.

Sections 5.8 to 5.10: the S-box and its inverse match FIPS 197 Tables 4 and 6 on all 256 entries, compared with an independent table. The course tables match that same table by SHA-256. Engine facts come from origin/main `7b569a1`. The four GeeksforGeeks pages were read through a summary tool. Section 5.11 checks the lines from Steve's paste, as relayed by the lead. The cybernews page itself is unread (HTTP 403).

Sections 5.12 and 5.13: ECB and CBC match the SP 800-38A F.1.1 and F.2.1 answers in independent Python. The GCM tag matches the course `Gcm.cs` in independent Python. Picture repeat counts come from the committed golden trace, and I did not run the lab. Recommendation: lessons state the IV and nonce rules per mode.

### 5.19 AES against the mode, and one flipped text bit

Rule: AES does its work inside one block. The mode decides what repeats show across blocks.

Measured with my own AES: 400 random keys, IVs and flips on `Pump four is ok.` x 4.

| Item | ECB | CBC |
|---|---|---|
| Cipher blocks changed by one text bit in block k | Block k only, 400 of 400 | Block k and all later blocks, 400 of 400 |
| Different cipher blocks from 4 equal text blocks | 1 | 4 |

Bits changed per changed block, both modes: 1,402 blocks, mean 63.8 of 128, range 45 to 84. "About half" is the later word avalanche, and it is a measured result (see 5.17).

Do not mix this with a flipped CIPHER bit, which damages differently on decrypt (section 2.4 of the design). Do not write "ECB lacks diffusion" (the across-blocks sense, seen in some sources, from recollection). It reads as a fault in AES. The mapping of S-box to confusion and ShiftRows plus MixColumns to diffusion stays labelled as common teaching.

Correction to the wording above, 2026-11-06. On screen, write "equal text blocks give equal cipher blocks". ECB shows a repeat only when 16 equal bytes fill a whole block in both places. Starting on a block boundary is neither needed nor enough (my run: 3 equal bytes on a boundary gave 0 repeats, and 39 equal bytes 3 bytes past a boundary and 48 apart gave 1).

Padding: PKCS#7, RFC 5652 section 6.3 (read 2026-11-06): "k-(lth mod k) octets all having value k-(lth mod k)", and input already a multiple of the block size is padded too. `Lesson01Aes.Pad` follows it. The one-block view adds nothing at 16 bytes, so that view keeps "teaching fill".

### Setup note: Electron binary in a fresh worktree (2026-11-06)

`npm ci` in a new worktree left `app/node_modules/electron/dist` with only `locales/`, and no `path.txt`. `node install.js` did not supply the binary. The cause is not found. `start.spec` then fails with "Electron failed to install correctly". Workaround used: copy `dist/` and `path.txt` from another tree at the same version (33.2.1). Cost: 1 failed test in a 14.5-minute run, and one rerun.

### 5.20 GCM nonces, counters and limits (read 2026-11-06)

Sources: SP 800-38D, RFC 8446, `src/NetSec.Core/Crypto/Gcm.cs`.

| Fact | Source |
|---|---|
| One IV per message under one key. A 32-bit counter changes per block | 38D 8, 7.1 step 3, 6.5 step 5, 6.2 |
| With a 96-bit IV, J0 = IV, then 31 zero bits, then a 1. J0 makes the tag mask. Text starts at inc32(J0), which is count 2 | 38D 7.1 steps 2, 3, 6. `Gcm.cs:55`, `:90` to `:96`, `:108` |
| 100,000 bytes = 6,250 blocks, counts 2 to 6,251. 250,000 bytes = 15,625 blocks, counts 2 to 15,626 | Arithmetic |
| The rule: the chance of one key and one IV on 2 different sets of input stays at or below 2^-32 | 38D 8 |
| Reuse repeats the key stream, and it can also give away H, which allows forgery | 38D Appendix A |
| Text limit: 2^39 - 256 bits = 68,719,476,704 bytes = 2^32 - 2 blocks. That is about 64 GiB, or 68.7 GB | 38D 5.2.1.1 |
| Counts 2 to 2^32 - 1 are 2^32 - 2 values, so the limit fits the counter. 38D states the limit and gives no reason in words. Label the link as our reading | Arithmetic |
| A record holds at most 2^14 bytes of content. The inner plaintext is at most 2^14 + 1 bytes, with the type byte. Padding counts inside that limit, and `record_size_limit` can lower it | RFC 8446 5.1, 5.2, 5.4 |
| Each record's nonce = 64-bit sequence number, padded left, XOR the static write IV. The number starts at 0 for each key | RFC 8446 5.3 |
| AES-GCM in TLS 1.3: about 24 million full records per key, 2^24.5 | RFC 8446 5.5 |
| An IV that is not 96 bits: J0 comes from GHASH. 96 bits is the recommended length | 38D 7.1 step 2, 5.2.1.1 |
| Random IVs, or IVs not 96 bits: at most 2^32 messages per key. A 96-bit deterministic IV does not have this limit | 38D 8.3 |
| Our engine takes only a 12-byte nonce | `Gcm.cs:117` |

Later checks, 2026-11-06:

| Fact | Source |
|---|---|
| 2^64 is TLS 1.3's sequence number size, not a GCM limit. GCM's deterministic IV limit comes from its fields: no two inputs may share an invocation field under one fixed field, so a 96-bit IV with a 32-bit fixed field leaves 2^64 values, and other splits leave other counts | RFC 8446 5.3. 38D 8.2.1 |
| 2^24.5 full records per key is a confidentiality and integrity limit on how much data one key protects, with a safety margin of about 2^-57. It is not about nonce repeats, because the sequence number gives a new nonce long before that | RFC 8446 5.5 |
| TLS 1.3 changes a key mid-connection with KeyUpdate, and the sequence number restarts at 0 | RFC 8446 4.6.3, 5.3 |
| 38D suggests, and does not require, that 32-bit fixed field and 64-bit invocation field split. KeyUpdate changes the sender's keys and IV, in one direction, after Finished. RFC 8446 says SHOULD update before the limit | 38D 8.2.1. RFC 8446 4.6.3, 5.5 |

## 5.21 Sealed chain cases, run (2026-11-06, verifier 6469627)

Sample and commands: `C:/Users/smuch/AppData/Local/Temp/claude/3097a1816bc1384a/cb141024-1785-4e15-96bb-23f4155ffdf2/scratchpad/sealed-sample/COMMANDS.txt`.

| Case | Section 7 walk | Command line, `verify --ledger` |
|---|---|---|
| Intact | PASS | PASS (full, key-bound), exit 0 |
| Last event cut, old seal | FAIL step 10, `merkle root mismatch — ledger contents do not produce sealed root` | FAIL merkle-root, `merkle root does not match (recomputed=..., claimed=...)`, exit 1 |
| Rewritten with the key, old seal | FAIL step 10, same words | FAIL merkle-root, same words, chain-linkage PASS |
| Rewritten, root replaced, old signature | FAIL step 11, `signature verification failed` | FAIL seal-signature, `seal signature does not verify under the supplied public key` |
| Rewritten, signed with the writer's own key, real public key | FAIL step 11, same words | FAIL seal-signature, `signing_key_fingerprint does not match supplied public key` |
| Same file, writer's public key | PASS | PASS, exit 0 |

Limits:
1. `verify --audit-file` takes no seal. Steps 10 and 11 of the section 7 walk are reachable from a program or a test vector only.
2. The last row is why the public key must come from a source other than the file's holder.
3. The ledger format is older than the section 7 format: per-event keys and an unkeyed `entry_hash` chain. Its tag is not the mock's `tag = HMAC(session key, previous tag + event)`.

## 5.22 Diffie-Hellman words, lesson 3 (2026-11-06)

1. SP 800-57 Part 1 Rev. 5, Table 2 (read in the PDF): 112 bits at L = 2048 with N = 224; 128 bits at L = 3072 with N = 256. The strength needs both numbers. L alone is not the claim.
2. RFC 7748: abstract says "~128-bit". Section 7 says curve25519's level "is slightly under the standard 128-bit level".
3. RFC 8446 section 4.4.3: the signature covers `Transcript-Hash(Handshake Context, Certificate)`. PSK alone loses forward secrecy for application data (section 2.2).
4. Mock n = 23, g = 5: g has order 22. Of 484 pairs, 10 make the listener's product equal the secret, each with a + b = a x b mod 22. Those pairs: (2,2), (4,16), (6,10), (8,20), (10,6), (14,18), (16,4), (18,14), (20,8), (22,22).
5. Private number 22 gives public number 1 and secret 1.

## 5.23 Hidden wire ranges, checked by decryption (2026-11-06, main 4f90948, seed 7)

Lesson 1: 6 of 6. Lesson 6 `pinBlock` 16 to 31: 4 of 4, ISO 9564 format 4, with PAN block from 4111111111111111. Lesson 7 TLS 1.1 `cipher` after header and IV: 5 of 5, holding text, 20-byte MAC and padding. Lesson 8 SSH `encryptedPacket`: 40 of 40, 24 CTR then 16 CBC, length inside. Lesson 9 SSH: 11 of 11. Scripts: `C:/Users/smuch/AppData/Local/Temp/claude/3097a1816bc1384a/cb141024-1785-4e15-96bb-23f4155ffdf2/scratchpad/r182/decrypt.py`, `more.py`, `ssh2.py`.
