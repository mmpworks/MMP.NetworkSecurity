# Algorithm optimization PRD

Status: DRAFT, 2026-11-10. Owner of the decision: Steve. Branch: `Algorithm-Optimization`. Worktree: a separate checkout, so `main` stays free for other teams.

## 1. What and why

1. The crypto code in `src/NetSec.Core/Crypto` and `src/NetSec.Core/Dukpt` is correct and easy to read. It is slow and it allocates memory on each block.
2. The targets are mobile devices and embedded computers that run Windows CE 6 with .NET Compact Framework 3.5 (CF). The same source also compiles for .NET 10.
3. This work makes the product path small, fast and safe for many threads. It keeps the code CUPID and DRY. It uses SOLID only where the first two give no answer.

## 2. Facts found on main at 5c5d4a4

| # | Fact | Where |
|---|------|-------|
| 1 | `AesKey` builds the S-box, the inverse S-box and 6 multiply tables in a static constructor. | `Crypto/AesKey.cs` lines 26 to 38, 169, 194 |
| 2 | `EncryptBlock` and `DecryptBlock` allocate 2 arrays of 16 bytes for each block. | `Crypto/AesKey.cs` |
| 3 | The round works on bytes through index maps (`ShiftRowsMap`). | `Crypto/AesKey.cs` |
| 4 | The lesson path is separate: `AesKey.Walk.cs`. It checks itself against the product path and throws `AES_WALK_DIVERGED`. | `Crypto/AesKey.Walk.cs` |
| 5 | One source, two builds: `NetSec.Core` (net10) and `NetSec.Core.NetCF` (net35, `NETCF` defined). Both use `LangVersion` 3 (design decision D1). | the two csproj files |
| 6 | Known-answer vectors exist for AES, AES modes, GCM, CMAC, TDES, SHA, SHA-3, HMAC, HKDF, X25519, RSA. | `acceptance/vectors` |
| 7 | No benchmark project exists. | repo file list |
| 8 | MMP.GasPumpSimulator caps the thread pool at 25 threads to copy the CF pool, and runs workers behind `IDispatchStrategy`. | `GasPump.Dispenser/Program.cs`, `GasPump.Dispatch` |

## 3. Acceptance (the anchor, written before any product change)

Echo writes these. Builders never write `acceptance/`.

| ID | Check | Pass rule |
|----|-------|-----------|
| AO-1 | Known-answer vectors, each algorithm, net10 build and CF build. | N of N pass |
| AO-2 | Differential test. A frozen copy of the main 5c5d4a4 code is the reference. Random keys, lengths and offsets go through the reference and the new code. | 1,000,000 cases for each algorithm, 0 differences |
| AO-3 | Table proof. A test builds each constant table from the math and compares it with the constant in the product. | every table equal |
| AO-4 | Thread test. One shared key object. A payload worker encodes and decodes on `ThreadPool.QueueUserWorkItem` with the pool capped at 25. Results equal the single-thread results. | 100,000 payloads, 0 mismatches, 10 runs |
| AO-5 | Allocation. Bytes allocated after warm-up, net10: for each block for AES, modes, TDES and hash blocks, for each message for HMAC with an `HmacKey`, and for each DUKPT key derivation. | 0 B for each block for AES, modes, TDES and hash blocks; 0 B for each message for HMAC through `HmacKey.Compute` with a caller-owned work object and output buffer; 0 B for each DUKPT derivation and for each call of a caller-buffer form (section 7.4) |
| AO-6 | Speed. Baseline at 5c5d4a4 and the new code, same machine, same run. | the report shows both numbers; AES target is 5 times baseline or better. The report line "CF ARM speed: UNMEASURED" stays until a run on a CE device exists |
| AO-7 | The lesson walks still agree with the product path. | no `AES_WALK_DIVERGED`; golden files unchanged. The byte-level helpers the walk uses today move into `AesKey.Walk.cs` unchanged. The walk calls word-path code only through `EncryptBlock` and `DecryptBlock` for the last compare |
| AO-8 | The CF build compiles, and the CF golden labs pass. | gate green |
| AO-9 | File benchmark (ordered by Steve on 2026-11-11). Real files go through the frozen 5c5d4a4 code and the new code in one run: seal and open with GCM, encrypt and decrypt with CBC and CTR, SHA-256 and HMAC. Each row records time, bytes allocated, peak memory and garbage collection counts. | the output bytes of the two codes are equal for each file; the report shows both number sets side by side; section 3.3 gives the rules |

Limit of the anchor: AO-2 uses our own old code as the reference. AO-1 (public vectors) is the independent check.

### 3.1 Case rules for AO-2 and AO-4 (added 2026-11-10 after the test review)

1. Scope of "each algorithm" in AO-2: AES block, ECB, CBC, CTR, GCM, CMAC, DES, TDES, MD5, SHA-1, SHA-256, SHA-512, SHA-3, SHAKE, HMAC, HKDF, the TLS PRFs, DUKPT derivation, PIN block. The count for RSA, P-256, 25519 and ML-KEM is set at S5.
2. Second referee on .NET 10: `System.Security.Cryptography` runs the same cases where it has the algorithm. CMAC, DUKPT, PIN block and SHAKE have the frozen reference and the vectors only. The report says so.
3. The frozen reference comes from a script that reads the files at 5c5d4a4 and changes only the namespace line. The check rebuilds the copy and fails on any byte difference.
4. Aliasing is a case axis: separate arrays, the same array at the same offset, and the same array shifted by 1 to 15 bytes in each direction.
5. Each output buffer has random guard bytes on both sides. A changed guard byte is a difference.
6. Input, IV, nonce, AAD and key bytes are compared before and after each call.
7. Invalid cases are part of the run (bad offset, bad length, key length 0, 15, 17, null). The exception type and machine code must match. A GCM open with a changed tag, AAD or ciphertext must return false with the same output state.
8. Lengths are weighted to 0, 1, 15, 16, 17, 31, 32, 33 and block multiples plus or minus 1, then uniform to 4096 or more.
9. AES key sizes 16, 24 and 32 are drawn equally. Decrypt of random ciphertext is compared with the reference.
10. A share of cases starts near the counter limits: CTR at all-FF, the GCM 32-bit counter wrap, and GCM nonces with a length other than 12.
11. Each hash case runs once whole and once in random chunk splits, with 0-byte updates and splits at 63, 64, 65, 127, 128 and 129. A mid-stream `Clone()` continues as two separate states. HMAC keys longer than the block and HKDF output up to the limit are included.
12. AO-4 runs in its own process, because the pool cap is for the whole process. AO-4 uses a fresh key object for each run, and the first call to each method occurs from many workers at the same time. One callback calls back into the same key. All modes, GCM and HMAC on shared keys are mixed in one run. The check asserts the result of `ThreadPool.SetMaxThreads(25, 25)` and prints the cap it got.
13. AO-3 has two kinds of row. A table row compares a table with the math. A start-up row fails when table-building code runs at start-up. Section 4.3 gives the state of each row before S1.
14. Each run records its seed and prints it in the report. A failed case prints the seed and the case number.
15. AO-2 runs on .NET 10 with the net10 binaries, and on .NET Framework 4.8 with the CF binaries. The second referee (rule 2) runs on .NET 10 only. After S6, the .NET 10 run covers the portable path and the hardware path (rule 7.1.13).
16. AO-4 matches each result to its payload by a payload ID, because the pool does not keep order.

### 3.2 Limits of the anchor

1. The "cf" build runs on the .NET Framework 4.8 desktop runtime in the gate. No check runs on the CF runtime or on a CE device. The CF JIT and the CF memory model are not covered.
2. Big-endian targets are not covered.
3. Timing leaks are not covered (non-goal 3).

### 3.3 File benchmark rules (AO-9)

1. The test files are in the repository, in one folder, with a list that gives each file's name, size and SHA-256. The run fails when a file differs from the list.
2. The set has one file of each kind: a PDF, a PNG image, a plain text file, a CSV file, a JSON file, a small binary file of 1 KB, and one large file of 4 MB or more. Small and large sizes are both present, because a pump message is small and a document is large.
3. Each file is made by us or is already in this repository under its licence (for example a PNG from `docs/screens`). A script makes the PDF, the CSV and the large file from a fixed seed. No file comes from a third party.
4. For each file and each operation, the run measures the frozen 5c5d4a4 code and the new code in the same process, on the same machine, after a warm-up. It gives the median of 15 runs or more, and the spread.
5. Each row records: megabytes for each second, bytes allocated for each call, peak working set, and the count of generation 0, 1 and 2 collections.
6. The run also records the cost for a small message: time and bytes for one key setup plus one 64-byte seal.
7. The same measurement runs with the CF binaries on .NET Framework 4.8, as a second desktop number. CF ARM speed stays UNMEASURED.
8. A second measurement repeats the run with 25 pool threads that share one key, and records total megabytes for each second and peak memory.
9. The report is one file in `docs/_runs/`, with one table: file, operation, original, new, ratio. A styled page for Steve shows the same numbers.
10. The suite, and not the benchmark, checks the file list, compares the output of the two codes for each file, and measures the AO-5 bytes. The file list with each name, size and SHA-256 is in `acceptance/`. The benchmark numbers for these are a second record. A difference between the suite and the benchmark is a red. The benchmark alone gives the AO-6 and AO-9 times.

## 4. Kill condition

The work ends when one head of `Algorithm-Optimization` shows the result below after slices S1 to S4, with the numbers in `docs/_runs/`. Target date: 2026-11-17. Slices S5, S6 and S7 are outside the kill condition, and each has its own go or stop decision.

### 4.1 The row list

1. Echo owns one row list in `acceptance/`. It has one line for each AO row ID, with no wildcards.
2. Each line has 4 fields: the row ID, the state before its slice, the reason code of that state, and the slice from which the row is PASS.
3. The state text is the text the harness prints, for example `PASS`, `FAIL` or `NOT RUN, PRODUCT_MISSING`.
4. A check in the suite compares each run with the row list. It needs the current slice as an input. The report gives N of M rows, and M is the number of lines in the row list.

### 4.2 The rule

1. Before its slice, a row shows the state and the reason code in the row list.
2. From its slice on, a row shows PASS.
3. Any other state, at any time, is a red. A FAIL with a different reason code is a red. A row in the run that is not in the list is a red. A row in the list that is not in the run is a red.

### 4.3 What the list must contain

| Rows | Before the slice | PASS from |
|------|------------------|-----------|
| AO-3 rows for AES tables built at start-up | `FAIL AO_TABLE_BUILT_AT_STARTUP` (fact 1) | S1 |
| AO-3 rows for the GHASH table | `NOT RUN NO_TABLES` | S1 |
| AO-4 rows for a shared `GcmKey` | `NOT RUN PRODUCT_MISSING` | S1 |
| AO-5 rows for AES and modes | `FAIL AO5_ALLOCATES` (fact 2) | S1 |
| AO-5 rows for the hash block loop of MD5, SHA-1, SHA-256 and SHA-512 | `PASS` (the loop allocates 0 bytes today) | S0 |
| AO-5 rows for the Keccak block loop and for HMAC | `FAIL AO5_ALLOCATES` | S3 |
| AO-5 rows for one whole hash message (MD5, SHA-1, SHA-256, SHA-512, Keccak) | `FAIL AO5_ALLOCATES` | S3 |
| AO-5 rows for the caller-buffer forms of the AES modes, CMAC and GCM (section 7.4 rule 2) | `NOT RUN PRODUCT_MISSING` | S1 |
| AO-5 rows for the caller-buffer forms of the hashes, HMAC, HKDF and the TLS PRFs | `NOT RUN PRODUCT_MISSING` | S3 |
| AO-5 rows for the caller-buffer forms of TDES, DUKPT derivation and the PIN block | `NOT RUN PRODUCT_MISSING` | S4 |
| AO-9 suite rows (file output equality) | `NOT RUN AO9_FILES_ABSENT` until the test files are in the tree, then `PASS` | S0 |
| AO-5 row for TDES | `PASS` (the block path allocates 0 bytes today) | S0 |
| AO-5 row for DUKPT derivation | `FAIL AO5_ALLOCATES` | S4 |
| AO-2 rows for `HmacKey.Compute` | `NOT RUN PRODUCT_MISSING` | S3 |
| AO-4 rows for the payload worker | `NOT RUN PRODUCT_MISSING` | S2 |
| AO-7 row for the walk helpers | `FAIL AO_WALK_CALLS_AESKEY_HELPER` | S1 |
| AO-3 rows for hash and DES tables | `NOT RUN PRODUCT_MISSING` | S3 and S4 |
| AO-2 row for the hardware path on .NET 10 | `NOT RUN PRODUCT_MISSING` | S6, outside the kill condition; it reads NOT RUN at the kill head |
| Rows for the big-number paths | `NOT RUN PRODUCT_MISSING` | S5, outside the kill condition; they read NOT RUN at the kill head |

AO-6 and AO-9 are records at S0: the run stores the baseline numbers and judges nothing. From S1, the AO-9 report compares the frozen code with the new code. The AES target of 5 times baseline is judged from S1.

S0 is done when the row-list check reads M of M for slice S0.

## 5. Non-goals

1. No new algorithm.
2. No change to wire formats, lesson text or golden files.
3. No claim of constant-time AES. Table lookups with secret indexes can leak through the CPU cache. The class comment says this today and it stays. The GHASH key in GCM is secret too, and its table lookups have the same limit.
4. No NuGet publish.

## 6. Decisions

| # | Decision | Pick | Status |
|---|----------|------|--------|
| 1 | Language level for the .NET 10 fast paths. | D1 stays: both builds use C# 3. The fast paths use `unsafe` pointers and the `System.Runtime.Intrinsics` types behind `#if !NETCF`. A spike on net10 with `LangVersion` 3 ran `Aes.Encrypt` and `Pclmulqdq.CarrylessMultiply` and printed `out[0]=99` (0x63, correct for a zero block and zero key). A higher level on one build can make one shared file bind in two ways, so the CF build would no longer prove what the net10 build runs. | confirmed by Steve on 2026-11-10: shared files stay C# 3, fast paths for newer runtimes go in separate `#if !NETCF` files |
| 2 | Table size for AES. | Default: 1 table of 1 KB plus rotates for each direction, and a 256-byte inverse S-box. The forward S-box comes from the encrypt table. The 4-table shape (8 KB for both directions) competes with the stack and the data in a small data cache (16 KB is an example size, UNVERIFIED for any named device). S1 measures both shapes on .NET 10 and on the CF binaries on .NET Framework 4.8. The pick is reviewed when a CE device number exists. | set as default |
| 3 | How the long branch reaches main. | Each slice is a PR into `Algorithm-Optimization`. One PR to `main` at the end, on Steve's order. | set |
| 4 | GHASH table. | A 4-bit table for each key: 16 entries of 4 `uint`, 256 bytes, plus one constant reduction table. | set |

## 7. Program design

### 7.1 Shape rules for every algorithm

1. No table is built by code. Each table is an array initializer with literal values. The type has no explicit static constructor.
2. A key object is immutable after its constructor. No instance method writes an instance array after the constructor. No per-key data is built on first use. All working state is in locals or in a buffer the caller owns. This makes a key object safe to share with no lock.
3. No allocation in a per-block or per-message-chunk path. No static scratch buffer and no thread-static scratch buffer.
4. State is 32-bit words in locals where the algorithm allows. Hot 32-bit loops use no `long` math. SHA-512 and Keccak are 64-bit by design; S3 measures bit interleaving for Keccak as an option.
5. A method copies each static table reference into a local at its start.
6. One implementation of each piece of knowledge. Example: one word-load helper, one XOR-block helper, one padding helper. A helper is inlined by hand only where the numbers of that slice show a gain against the helper version, and AO-2 covers each inlined copy.
7. `#if NETCF` only at a named seam, never inside a round function.
8. Unproven for the CF JIT, so no rule depends on them: removal of bounds checks, the inline size limit, and a rotate instruction for `(x >> 8) | (x << 24)`.
9. A block function reads all its input into locals before its first output write. This is what makes overlapped input and output correct.
   A mode over many blocks keeps the block order of the 5c5d4a4 code. When the output starts 1 to 15 bytes after the input in the same array, the result must equal the reference result. The mode does not reject the overlap and does not reverse the loop.
10. Argument checks stay at the public boundary, with the exception types and machine codes of today. No check is inside a round loop.
11. The walk reads the key schedule through an internal read path. No public member returns an instance array.
12. All `NETCF` seams are listed in one table in `docs/`, so a reviewer can count them. A gate check counts the `#if NETCF` and `#if !NETCF` lines in `src/NetSec.Core` and fails when the count differs from the table rows.
13. The net10 build has a named seam that forces the portable word path. The seam is an internal constructor argument on the key. No static switch changes the path during a run. AO-2 on .NET 10 runs the portable path and the hardware path.

### 7.2 Slices

| Slice | Content | Owner | Review |
|-------|---------|-------|--------|
| S0 | Anchor AO-1 to AO-8, frozen reference, benchmark project, baseline numbers for net10 and CF. | Echo (anchor), Richard (benchmark) | Jared |
| S1 | AES: constant tables, word state, no allocation, word key schedule, equivalent inverse cipher. Modes, CMAC, GCM with `GcmKey` (decision 4). | Richard | Jared |
| S2 | `AesPayloadWorker`: encode and decode payloads on the thread pool, modelled on the GasPumpSimulator dispatch pattern. Bounded queue, pool cap 25, no shared scratch. | Richard | Jared, Echo runs AO-4 |
| S3 | Hashes: MD5, SHA-1, SHA-256, SHA-512, Keccak. `HmacKey` keeps the two padded key states. HKDF and the TLS PRFs reuse them. | Richard | Jared |
| S4 | DES and TDES with constant combined tables. DUKPT derivation and PIN block paths without per-step allocation. | Richard | Jared |
| S5 | Big-number paths: `BigUInt`, Montgomery, RSA, P-256, 25519, ML-KEM. Highest risk. Starts only after S0 numbers show it is worth it. | to assign | Jared |
| S6 | .NET 10 fast paths behind `#if !NETCF` (hardware AES and carry-less multiply), with pointers at C# 3 (decision 1). | Richard | Jared |
| S7 | Release selector in the app. The code view gets a control to pick the release (CE with CF 3.5, or .NET 10). The view then shows the code that release runs, so a learner can read the fast path for each release. Ordered by Steve on 2026-11-10. The design comes after S1, when the first fast-path file exists. | to assign | Jared, Echo |

The S0 benchmark list includes AES key setup (both schedules). The row for the CF build reads "CF binaries on net48 desktop JIT". It is not a CF number.

### 7.3 Types and signatures to confirm in S0 (hypothesis)

1. `AesKey.EncryptBlock(byte[] i, int io, byte[] o, int oo)` and `DecryptBlock` keep their signatures. The constructor builds the plain key schedule (the walk reads it) and the decrypt schedule.
2. `GcmKey` (immutable): holds an `AesKey` and the GHASH table. Its methods have the names and parameters of the static `Gcm` methods, without the key: `byte[] Seal(byte[] nonce, byte[] aad, byte[] plain)` and `bool TryOpen(byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain)`. The static `Gcm` methods stay as wrappers.
3. `HmacKey` (immutable): holds the inner and outer padded hash states. `IHash` keeps `Clone()` as its state copy. `Hmac.Compute` stays as a wrapper.
4. `AesPayloadWorker(GcmKey key, int maxQueued)`. `bool TryEncode(int id, byte[] nonce, byte[] plain, Action<PayloadResult> done)` and `bool TryDecode(int id, byte[] wire, Action<PayloadResult> done)`. `PayloadResult` carries the ID, the bytes, or a machine error code.
5. The worker catches each exception on the pool thread and reports it through `PayloadResult`. An exception that leaves a pool thread ends the process.
6. The caller supplies the nonce for each payload. The worker holds no nonce counter. The caller must never use a nonce two times with one key. The worker does not check this.
7. Dispatch is a seam. The worker gets an `Action<WaitCallback>` that queues work. The default is `ThreadPool.QueueUserWorkItem`. The host program sets the pool cap; the worker never calls `SetMaxThreads`.
8. `TryEncode` and `TryDecode` never block. An `Interlocked` counter holds the number of pending payloads, and a call returns false when the counter is at `maxQueued`. The order is: increment, then read a `volatile` disposed flag; if the flag is set, decrement and return false. The worker decrements in a `finally` after `done` returns or throws. If the dispatch delegate throws, the worker decrements and the call returns false. CF 3.5 has no `Monitor.Wait`, no `Monitor.Pulse` and no `Semaphore`, so a blocking queue is out of scope.
9. The worker also catches an exception that the `done` callback throws, and counts it. It does not call `done` again for that payload.
10. Stop rule: after `Dispose`, `TryEncode` and `TryDecode` return false. Each payload already queued still gets its `done` call. `Dispose` does not wait. The worker has an `Idle` event that is set when the counter is 0, and a caller that must wait uses it.
11. Wire layout for a payload: 12-byte nonce, ciphertext, 16-byte tag. This is a new layout that only the worker uses. Non-goal 2 covers the layouts that exist today. `TryEncode` rejects a nonce that is not 12 bytes, with a machine code. `TryDecode` rejects a wire shorter than 28 bytes, with a machine code. On a tag failure, `PayloadResult` carries the error code and no plaintext bytes. The 4 bytes of the payload ID are the AAD, so a payload moved to a different ID fails its tag. The layout has no replay check: the same wire with the same ID decodes again. The caller owns replay defence.
12. The call sites that seal many records with one key (the TLS record paths) hold a `GcmKey`. S1 lists them. A static `Gcm` wrapper builds a `GcmKey` on each call, so it is for single calls only.
13. S0 measures AES key setup. If the decrypt schedule in every constructor costs too much for per-transaction keys (DUKPT), an encrypt-only constructor is the fallback, and that needs a decision.
14. HMAC with no allocation uses a working hash that the caller owns: `HmacKey.Compute(IHash work, byte[] data, int off, int len, byte[] mac, int macOff)`. One thread uses a work object at a time. The key copies its saved state into the work object through a copy-into method on the hash (hypothesis: `void CopyStateTo(IHash target)`), which throws a machine code when the target type differs. `Hmac.Compute` stays as a wrapper that allocates.

### 7.4 Zero-garbage rules (ordered by Steve on 2026-11-11)

Steve's order: reduce or remove memory allocation in these paths, most of all on the 3.5 build, so that the garbage collector has less to do. A design that removes the need for an allocation is better than one that makes the allocation cheaper.

Why it matters on the 3.5 build: every allocated byte brings the next collection closer, and a collection stops the program. Today a GCM seal of a 4 MiB file allocates about 25 MB (262,144 blocks at about 96 bytes each). How often the Compact Framework collector runs for a given amount of allocation is not measured in this project; the benchmark records collection counts on the .NET 3.5 desktop runtime as the nearest evidence.

The rules, in order of preference:

1. No state on the heap. A block function keeps its state in local words. It makes no array.
2. The caller owns the buffers. Each operation that produces bytes has a form that writes into a buffer the caller gives: `(byte[] input, int inOffset, int count, byte[] output, int outOffset)`. The form that returns a new array stays as a thin wrapper over it. This holds for ECB, CBC, CTR, GCM seal and open, CMAC, each hash `Finish`, HMAC, the TLS PRFs, HKDF, the DUKPT derivation and the PIN block.
3. In-place work is legal. Input and output may be the same array at the same offset, so a caller can encrypt a buffer with no second buffer. The modes keep the block order of the 5c5d4a4 code (rule 7.1.9).
4. A key object holds all it needs for its life: round keys, the GHASH table, the padded HMAC states. It builds them one time, in its constructor. No call builds them again.
5. A running operation that needs state between calls keeps it in an object the caller owns and can use again: a hash object has `Reset()`, and a mode with a running state (CTR counter, CBC chain, GCM tag state) takes a small state object from the caller. One thread uses a state object at a time.
6. The payload worker takes buffers from a bounded set that it owns, built one time, and gives each buffer back when its `done` call returns. Taking and giving back use `Interlocked` only. When the set is empty, `TryEncode` returns false; the worker does not allocate a new buffer in its place.
7. No hidden allocation in a hot path: no closure or delegate made for each call, no `params` array, no boxing of a value type, no string building, no `foreach` over an interface, no exception used for flow.
8. A check that compares a tag or a digest uses the bytes where they are. It makes no copy to compare.

What stays allocated, by design: one key object for each key, the buffers a caller makes, and the lesson walk (it records steps, and it is no product path).

The test rows for these rules are in section 4.3: each AO-5 block row, each AO-5 message row, and one AO-5 row for each caller-buffer form (0 bytes for each call, with the output array included, because the caller made it).
### 7.5 When form and the goals disagree (Steve, 2026-11-11)

Steve's words: "try to be CUPID and DRY, but we may need to bend the rules a bit to get the performance and memory goals met."

1. The order of weight in a hot path is: correct output, then the memory and speed goals, then CUPID and DRY.
2. A bend is allowed only where a number shows the gain. The number is the benchmark ratio outside the measured noise band, or the AO-5 byte count.
3. Each bend has a comment at its place in the code. The comment names the rule that is bent, the reason, and the measured gain. Example: a round that is written out two times because a shared helper costs a call on the 3.5 runtime.
4. A bend stays inside one type. The public shape of a type stays simple and the same for all callers.
5. A copy made for speed is covered by the same tests as its source: AO-1 and AO-2 run each copy.
6. Outside the hot paths (key setup that runs one time, error paths, the lesson walk) the form rules have no exception.
7. The reviewer rules on each bend. A bend with no number is a blocker.

## 8. Boundary and failure routing

1. Free without asking: edits in the `Algorithm-Optimization` worktrees, PRs into `Algorithm-Optimization`, heavy runs through `tools/heavy_lock.py`.
2. Needs Steve: the merge to `main`, any change to D1, any change to a lesson, golden file or wire format.
3. A red AO check stops the slice. The builder reports it. A rerun pass does not close it.
4. A CF API gap (for example thread-local storage) is a stop and report to the lead with the missing member named.

## 9. Disposition

Start S0 now. S1 starts when S0 has a red-to-green anchor and baseline numbers.
