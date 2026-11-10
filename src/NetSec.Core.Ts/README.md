# NetSec.Core.Ts: AES walk library (TypeScript)

This folder holds AES-128, AES-192 and AES-256 (FIPS 197) in TypeScript. It is the second engine beside the C# one in `src/NetSec.Core/Crypto/AesKey.cs`. Each walk function returns every intermediate byte as a step trace.

1. The library has no dependency, no DOM call and no Node API. It runs in a browser and in Electron.
2. Every function is pure. It copies its input and never changes it.
3. Every returned trace is frozen, down to each byte array.
4. Happy path only. The library has no tamper or injection feature.

## Run the checks

Node 24 runs the `.ts` files directly (type stripping). No build step is needed.

```
cd src/NetSec.Core.Ts
node --test "test/**/*.test.ts"
```

The type check uses the TypeScript compiler that `app/` already locks. Run `npm ci --ignore-scripts` in `app/` once, then:

```
npm run typecheck
```

`tsconfig.json` checks `src/` with no DOM library and no Node types, so a DOM or Node call in `src/` fails the check.

## Layout

| File | Job |
|------|-----|
| `src/bytes.ts` | Input checks, frozen output, hex, and `AesError` |
| `src/field.ts` | GF(2^8) multiply and the S-boxes |
| `src/cipher.ts` | The real AES path: key expansion, encrypt, decrypt |
| `src/walk.ts` | The step traces, checked against `cipher.ts` |
| `src/index.ts` | The public API |
| `test/fips197/` | The FIPS 197 values and the script that transcribed them |

## The checks

1. `test/fips197.test.ts` compares the walk with every value that FIPS 197 publishes: 156 key-expansion words (Appendix A) and 372 cipher and inverse-cipher values (Appendix C). The values are in `test/fips197/fips197-vectors.json`. `extract.py` transcribed them from the NIST PDFs. It does not use this engine.
2. `test/node-crypto.test.ts` compares 100 random key and block pairs per key size with `node:crypto` (`aes-N-ecb`, padding off).
3. `test/contract.test.ts` checks the trace contract: frozen output, untouched input, linked steps, and coded errors.

FIPS 197-upd1 (2023) removed Appendix C. The cipher traces therefore come from the 2001 edition. `extract.py` records the URL and SHA-256 of each PDF.

## Differences from the C# trace

The TypeScript trace carries the same information as `AesKey.Walk.cs`. These are the differences:

| Item | C# | TypeScript |
|------|----|-----------|
| Step state | `State`, the state after the step | `before` and `after`. An adapter maps `after` to `state` |
| Bytes | `byte[]` (hex strings in the host JSON) | frozen `number[]` (`Bytes`). `toHex` gives the JSON form |
| Key word number | `Index` (JSON `i`) | `index` |
| Step kind | `AesStepKind` enum | string union with the same names |
| `AesDoubling.shifted` | `int` (JSON: 3 hex digits) | `number` |
| Call shape | instance methods on `AesKey` | pure functions that take the key bytes |
| Block length | at least 16 bytes; the walk reads the first 16 | 16 bytes only; any other length throws `AES_BLOCK_LENGTH` |
| Errors | `ArgumentException` for the key length, `AES_WALK_DIVERGED` | `AesError` with `code`: `AES_KEY_LENGTH`, `AES_BLOCK_LENGTH`, `AES_BYTE`, `AES_HEX`, `AES_WALK_DIVERGED` |
| Tables | `SubstitutionTable()`, `ShiftMap(bool)` return copies | `SBOX`, `INVERSE_SBOX`, `SHIFT_ROWS_MAP`, `INVERSE_SHIFT_ROWS_MAP` are frozen constants |

Both engines use the same decrypt order: the inverse cipher of FIPS 197 section 5.3 (AddRoundKey before InvMixColumns). Both number a step by the round key its round uses: encrypt counts 0 to Nr, decrypt counts Nr down to 0. FIPS Appendix C numbers the inverse rounds in run order, so FIPS inverse round r is walk round Nr - r.

The lab objects in `src/NetSec.Core/Labs` (typed-text cut, long text, wire status) are outside this library.
