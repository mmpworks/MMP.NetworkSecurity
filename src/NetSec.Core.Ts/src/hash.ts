/**
 * SHA-256 (FIPS 180-4), HMAC-SHA-256 (RFC 2104) and HKDF (RFC 5869), with the TLS 1.3
 * label form (RFC 8446 section 7.1).
 *
 * 1. For the walk lessons: the key schedule of TLS 1.3 is a chain of these calls.
 * 2. Pure. No dependency, no DOM, no Node API. Practice use only: nothing here is constant time.
 */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
  0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
  0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
])

const rotr = (x: number, n: number): number => (x >>> n) | (x << (32 - n))

export const HASH_LEN = 32
const BLOCK = 64

/** SHA-256 of a byte sequence. */
export function sha256(data: ArrayLike<number>): Uint8Array {
  const len = data.length
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6)
  for (let i = 0; i < len; i += 1) padded[i] = data[i]
  padded[len] = 0x80
  const view = new DataView(padded.buffer)
  view.setUint32(padded.length - 8, Math.floor((len * 8) / 0x100000000))
  view.setUint32(padded.length - 4, (len * 8) >>> 0)

  const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19])
  const w = new Uint32Array(64)
  for (let off = 0; off < padded.length; off += BLOCK) {
    for (let t = 0; t < 16; t += 1) w[t] = view.getUint32(off + 4 * t)
    for (let t = 16; t < 64; t += 1) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3)
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10)
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0
    }
    let [a, b, c, d, e, f, g, hh] = h
    for (let t = 0; t < 64; t += 1) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      const ch = (e & f) ^ (~e & g)
      const t1 = (hh + S1 + ch + K[t] + w[t]) >>> 0
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const t2 = (S0 + maj) >>> 0
      hh = g
      g = f
      f = e
      e = (d + t1) >>> 0
      d = c
      c = b
      b = a
      a = (t1 + t2) >>> 0
    }
    h[0] = (h[0] + a) >>> 0
    h[1] = (h[1] + b) >>> 0
    h[2] = (h[2] + c) >>> 0
    h[3] = (h[3] + d) >>> 0
    h[4] = (h[4] + e) >>> 0
    h[5] = (h[5] + f) >>> 0
    h[6] = (h[6] + g) >>> 0
    h[7] = (h[7] + hh) >>> 0
  }
  const out = new Uint8Array(HASH_LEN)
  const ov = new DataView(out.buffer)
  for (let i = 0; i < 8; i += 1) ov.setUint32(4 * i, h[i])
  return out
}

function concat(...parts: ArrayLike<number>[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    for (let i = 0; i < p.length; i += 1) out[at + i] = p[i]
    at += p.length
  }
  return out
}

/** HMAC-SHA-256 (RFC 2104). */
export function hmacSha256(key: ArrayLike<number>, data: ArrayLike<number>): Uint8Array {
  const k = new Uint8Array(BLOCK)
  const base = key.length > BLOCK ? sha256(key) : key
  for (let i = 0; i < base.length; i += 1) k[i] = base[i]
  const ipad = k.map((b) => b ^ 0x36)
  const opad = k.map((b) => b ^ 0x5c)
  return sha256(concat(opad, sha256(concat(ipad, data))))
}

/** HKDF-Extract (RFC 5869 section 2.2): PRK = HMAC(salt, IKM). An empty salt is 32 zero bytes. */
export function hkdfExtract(salt: ArrayLike<number>, ikm: ArrayLike<number>): Uint8Array {
  return hmacSha256(salt.length === 0 ? new Uint8Array(HASH_LEN) : salt, ikm)
}

/** HKDF-Expand (RFC 5869 section 2.3): `length` bytes of output from PRK and info. */
export function hkdfExpand(prk: ArrayLike<number>, info: ArrayLike<number>, length: number): Uint8Array {
  if (length < 0 || length > 255 * HASH_LEN) throw new RangeError('HKDF-Expand: the length must be 0 to 8160 bytes.')
  const out = new Uint8Array(length)
  let t: Uint8Array = new Uint8Array(0)
  let at = 0
  for (let n = 1; at < length; n += 1) {
    t = hmacSha256(prk, concat(t, info, [n]))
    out.set(t.subarray(0, Math.min(HASH_LEN, length - at)), at)
    at += HASH_LEN
  }
  return out
}

const ascii = (text: string): number[] => Array.from(text, (c) => c.charCodeAt(0))

/**
 * The HkdfLabel of TLS 1.3 (RFC 8446 section 7.1): a 2-byte length, then "tls13 " + label and the
 * context, each with a 1-byte length in front.
 */
export function hkdfLabel(label: string, context: ArrayLike<number>, length: number): Uint8Array {
  const full = ascii(`tls13 ${label}`)
  return concat([length >> 8, length & 0xff], [full.length], full, [context.length], context)
}

/** HKDF-Expand-Label (RFC 8446 section 7.1). */
export function hkdfExpandLabel(secret: ArrayLike<number>, label: string, context: ArrayLike<number>, length: number): Uint8Array {
  return hkdfExpand(secret, hkdfLabel(label, context, length), length)
}

/** Derive-Secret (RFC 8446 section 7.1): Expand-Label with the hash of the messages as the context. */
export function deriveSecret(secret: ArrayLike<number>, label: string, transcriptHash: ArrayLike<number>): Uint8Array {
  return hkdfExpandLabel(secret, label, transcriptHash, HASH_LEN)
}

export const bytesToHex = (b: ArrayLike<number>): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16)
  return out
}
export { concat as concatBytes }
