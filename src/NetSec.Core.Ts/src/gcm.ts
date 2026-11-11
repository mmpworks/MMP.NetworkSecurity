/**
 * AES-GCM (NIST SP 800-38D): encryption with a tag that proves the data was not changed.
 *
 * 1. Built on the AES block cipher of cipher.ts. GCM uses only the forward cipher.
 * 2. `gcmParts` shows each value on the way: the hash key H, the first counter block J0,
 *    the key stream, the GHASH result and the tag. The record lessons use it.
 * 3. Pure and frozen. No Node API. Practice use only: nothing here is constant time.
 */
import { encryptWith, expandKey, type KeySchedule } from './cipher.ts'

export type GcmErrorCode = 'GCM_TAG_MISMATCH' | 'GCM_IV_LENGTH' | 'GCM_TAG_LENGTH'

export class GcmError extends Error {
  readonly code: GcmErrorCode
  constructor(code: GcmErrorCode, message: string) {
    super(message)
    this.name = 'GcmError'
    this.code = code
  }
}

const BLOCK = 16
const TAG_LEN = 16
/** The reduction constant of GHASH: x^128 + x^7 + x^2 + x + 1, with the bits in GCM order. */
const R = 0xe1n << 120n

const toBig = (b: ArrayLike<number>): bigint => {
  let v = 0n
  for (let i = 0; i < b.length; i += 1) v = (v << 8n) | BigInt(b[i])
  return v
}
const fromBig = (v: bigint): Uint8Array => {
  const out = new Uint8Array(BLOCK)
  let x = v
  for (let i = BLOCK - 1; i >= 0; i -= 1) {
    out[i] = Number(x & 0xffn)
    x >>= 8n
  }
  return out
}

/** One multiplication in GF(2^128), SP 800-38D algorithm 1. Bit 0 is the leftmost bit. */
function gfMul(x: bigint, y: bigint): bigint {
  let z = 0n
  let v = y
  for (let i = 127n; i >= 0n; i -= 1n) {
    if ((x >> i) & 1n) z ^= v
    v = v & 1n ? (v >> 1n) ^ R : v >> 1n
  }
  return z
}

const encryptBlockWith = (schedule: KeySchedule, block: ArrayLike<number>): Uint8Array =>
  Uint8Array.from(encryptWith(schedule, Object.freeze(Array.from(block))))

/** The length of a byte run in bits, as 8 bytes. */
function bitLength64(byteLength: number): Uint8Array {
  const out = new Uint8Array(8)
  let bits = BigInt(byteLength) * 8n
  for (let i = 7; i >= 0; i -= 1) {
    out[i] = Number(bits & 0xffn)
    bits >>= 8n
  }
  return out
}

/** The bytes of a GHASH input: each part filled with zeros up to a full block, then the 2 lengths. */
function ghashInput(aad: ArrayLike<number>, text: ArrayLike<number>): Uint8Array {
  const pad = (n: number): number => (BLOCK - (n % BLOCK)) % BLOCK
  const out = new Uint8Array(aad.length + pad(aad.length) + text.length + pad(text.length) + BLOCK)
  out.set(Array.from(aad), 0)
  out.set(Array.from(text), aad.length + pad(aad.length))
  out.set(bitLength64(aad.length), out.length - 16)
  out.set(bitLength64(text.length), out.length - 8)
  return out
}

/** GHASH over full blocks, SP 800-38D algorithm 2. */
function ghashBlocks(h: bigint, data: Uint8Array): Uint8Array {
  let y = 0n
  for (let at = 0; at < data.length; at += BLOCK) y = gfMul(y ^ toBig(data.subarray(at, at + BLOCK)), h)
  return fromBig(y)
}

/** GHASH of the associated data and the ciphertext, under the hash key H. */
export function ghash(h: ArrayLike<number>, aad: ArrayLike<number>, ciphertext: ArrayLike<number>): Uint8Array {
  return ghashBlocks(toBig(h), ghashInput(aad, ciphertext))
}

/** J0, the first counter block. A 12-byte IV gets the counter 1 after it; any other length goes through GHASH. */
function firstCounter(h: bigint, iv: ArrayLike<number>): Uint8Array {
  if (iv.length === 0) throw new GcmError('GCM_IV_LENGTH', 'The IV must have 1 byte or more.')
  if (iv.length === 12) {
    const j0 = new Uint8Array(BLOCK)
    j0.set(Array.from(iv), 0)
    j0[15] = 1
    return j0
  }
  const pad = (BLOCK - (iv.length % BLOCK)) % BLOCK
  const data = new Uint8Array(iv.length + pad + BLOCK)
  data.set(Array.from(iv), 0)
  data.set(bitLength64(iv.length), data.length - 8)
  return ghashBlocks(h, data)
}

/** The counter block after this one: the last 4 bytes count up, and wrap at 2^32. */
function inc32(block: Uint8Array): Uint8Array {
  const out = Uint8Array.from(block)
  for (let i = 15; i >= 12; i -= 1) {
    out[i] = (out[i] + 1) & 0xff
    if (out[i] !== 0) break
  }
  return out
}

/** Every value that GCM makes for one message. */
export interface GcmParts {
  /** H = AES(key, 16 zero bytes). The key of GHASH. */
  readonly h: Uint8Array
  /** J0: the counter block that makes the tag mask. */
  readonly j0: Uint8Array
  /** AES(key, J0). The tag is this XOR the GHASH result. */
  readonly tagMask: Uint8Array
  /** The key stream, one byte for each byte of text. Block i is AES(key, J0 + i), i from 1. */
  readonly keystream: Uint8Array
  /** `input` XOR `keystream`. */
  readonly output: Uint8Array
  /** GHASH(H, aad, ciphertext). */
  readonly ghash: Uint8Array
  readonly tag: Uint8Array
}

function parts(key: ArrayLike<number>, iv: ArrayLike<number>, input: ArrayLike<number>, aad: ArrayLike<number>, inputIsCiphertext: boolean): GcmParts {
  const schedule = expandKey(key)
  const h = encryptBlockWith(schedule, new Uint8Array(BLOCK))
  const hBig = toBig(h)
  const j0 = firstCounter(hBig, iv)
  const tagMask = encryptBlockWith(schedule, j0)
  const keystream = new Uint8Array(input.length)
  let counter = j0
  for (let at = 0; at < input.length; at += BLOCK) {
    counter = inc32(counter)
    keystream.set(encryptBlockWith(schedule, counter).subarray(0, Math.min(BLOCK, input.length - at)), at)
  }
  const output = Uint8Array.from(keystream, (k, i) => k ^ input[i])
  const hash = ghashBlocks(hBig, ghashInput(aad, inputIsCiphertext ? input : output))
  const tag = Uint8Array.from(hash, (x, i) => x ^ tagMask[i])
  return Object.freeze({ h, j0, tagMask, keystream, output, ghash: hash, tag })
}

/** Every value of one encryption. `output` is the ciphertext. */
export const gcmParts = (key: ArrayLike<number>, iv: ArrayLike<number>, plaintext: ArrayLike<number>, aad: ArrayLike<number> = []): GcmParts =>
  parts(key, iv, plaintext, aad, false)

/** Every value of one decryption. `output` is the plaintext and `tag` is the tag that the ciphertext must carry. This does not check the tag. */
export const gcmOpenParts = (key: ArrayLike<number>, iv: ArrayLike<number>, ciphertext: ArrayLike<number>, aad: ArrayLike<number> = []): GcmParts =>
  parts(key, iv, ciphertext, aad, true)

export interface GcmSealed {
  readonly ciphertext: Uint8Array
  /** 16 bytes. */
  readonly tag: Uint8Array
}

/** AES-GCM encryption. The key is 16, 24 or 32 bytes. The tag is 16 bytes. */
export function gcmEncrypt(key: ArrayLike<number>, iv: ArrayLike<number>, plaintext: ArrayLike<number>, aad: ArrayLike<number> = []): GcmSealed {
  const p = gcmParts(key, iv, plaintext, aad)
  return Object.freeze({ ciphertext: p.output, tag: p.tag })
}

/** AES-GCM decryption. A tag that does not match throws GcmError with the code GCM_TAG_MISMATCH, and no plaintext comes back. */
export function gcmDecrypt(key: ArrayLike<number>, iv: ArrayLike<number>, ciphertext: ArrayLike<number>, tag: ArrayLike<number>, aad: ArrayLike<number> = []): Uint8Array {
  if (tag.length !== TAG_LEN) throw new GcmError('GCM_TAG_LENGTH', 'The tag must have 16 bytes.')
  const p = gcmOpenParts(key, iv, ciphertext, aad)
  let diff = 0
  for (let i = 0; i < TAG_LEN; i += 1) diff |= p.tag[i] ^ tag[i]
  if (diff !== 0) throw new GcmError('GCM_TAG_MISMATCH', 'The tag does not match. The data or the associated data was changed, or the key is wrong.')
  return p.output
}
