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
| AO-5 | Allocation. Bytes allocated for each block after warm-up, net10. | 0 B for AES, modes and hashes |
| AO-6 | Speed. Baseline at 5c5d4a4 and the new code, same machine, same run. | the report shows both numbers; AES target is 5 times baseline or better |
| AO-7 | The lesson walks still agree with the product path. | no `AES_WALK_DIVERGED`; golden files unchanged |
| AO-8 | The CF build compiles, and the CF golden labs pass. | gate green |

Limit of the anchor: AO-2 uses our own old code as the reference. AO-1 (public vectors) is the independent check.

## 4. Kill condition

The work ends when slices S0 to S4 each show AO-1 to AO-8 green on one head of `Algorithm-Optimization`, with the numbers in `docs/_runs/`. Target date: 2026-11-17. Slice S5 has its own go or stop decision.

## 5. Non-goals

1. No new algorithm.
2. No change to wire formats, lesson text or golden files.
3. No claim of constant-time AES. Table lookups with secret indexes can leak through the CPU cache. The class comment says this today and it stays.
4. No NuGet publish.

## 6. Decisions

| # | Decision | Pick | Status |
|---|----------|------|--------|
| 1 | D1 says both builds use C# 3. Newer-runtime fast paths (hardware AES, `Span`) need a newer language level. | Shared files stay C# 3. Fast paths for .NET 10 go in separate files behind `#if !NETCF`, and only the net10 project raises its language level. The CF build proves the shared files stay C# 3. | Steve to confirm; S0 and S1 shared-code work does not depend on it |
| 2 | Table size for AES. | Measure two shapes on ARM-like limits: 4 tables of 1 KB for each direction, or 1 table plus rotates. Pick the smaller one if it is within 10% on speed. | Richard, with numbers |
| 3 | How the long branch reaches main. | Each slice is a PR into `Algorithm-Optimization`. One PR to `main` at the end, on Steve's order. | set |

## 7. Program design

### 7.1 Shape rules for every algorithm

1. Tables are constants in the source. No code builds a table at start-up.
2. A key object is immutable after its constructor. All working state is in locals or in a buffer the caller owns. This makes a key object safe to share with no lock.
3. No allocation in a per-block or per-message-chunk path.
4. State is 32-bit words in locals where the algorithm allows. The CF JIT is simple, so the source does the work the JIT skips: manual inlining of tiny helpers in hot loops, loop bounds on `array.Length`, no `long` math in 32-bit hot loops. Each of these is a hypothesis until S0 numbers confirm it (unverified, from recollection of CF behaviour).
5. One implementation of each piece of knowledge. Example: one word-load helper, one XOR-block helper, one padding helper.
6. `#if NETCF` only at a named seam, never inside a round function.

### 7.2 Slices

| Slice | Content | Owner | Review |
|-------|---------|-------|--------|
| S0 | Anchor AO-1 to AO-8, frozen reference, benchmark project, baseline numbers for net10 and CF. | Echo (anchor), Richard (benchmark) | Jared |
| S1 | AES: constant tables, word state, no allocation, word key schedule, equivalent inverse cipher. Modes, CMAC, GCM (GHASH with a per-key 4-bit table). | Richard | Jared |
| S2 | `AesPayloadWorker`: encode and decode payloads on the thread pool, modelled on the GasPumpSimulator dispatch pattern. Bounded queue, pool cap 25, no shared scratch. | Richard | Jared, Echo runs AO-4 |
| S3 | Hashes: MD5, SHA-1, SHA-256, SHA-512, Keccak. HMAC keeps the two padded key states. HKDF and the TLS PRFs reuse them. | Richard | Jared |
| S4 | DES and TDES with constant combined tables. DUKPT derivation and PIN block paths without per-step allocation. | Richard | Jared |
| S5 | Big-number paths: `BigUInt`, Montgomery, RSA, P-256, 25519, ML-KEM. Highest risk. Starts only after S0 numbers show it is worth it. | to assign | Jared |
| S6 | .NET 10 fast paths behind `#if !NETCF` (hardware AES and carry-less multiply). Needs decision 1. | Richard | Jared |

### 7.3 Types and signatures to confirm in S0 (hypothesis)

1. `AesKey.EncryptBlock(byte[] i, int io, byte[] o, int oo)` and `DecryptBlock` keep their signatures.
2. `AesPayloadWorker(AesKey key, int maxQueued)`, `bool TryEncode(byte[] plain, Action<byte[]> done)`, `bool TryDecode(byte[] wire, Action<byte[]> done)`. The payload framing follows the mode the Host already uses.

## 8. Boundary and failure routing

1. Free without asking: edits in the `Algorithm-Optimization` worktrees, PRs into `Algorithm-Optimization`, heavy runs through `tools/heavy_lock.py`.
2. Needs Steve: the merge to `main`, decision 1, any change to a lesson, golden file or wire format.
3. A red AO check stops the slice. The builder reports it. A rerun pass does not close it.
4. A CF API gap (for example thread-local storage) is a stop and report to the lead with the missing member named.

## 9. Disposition

Start S0 now. S1 starts when S0 has a red-to-green anchor and baseline numbers.
