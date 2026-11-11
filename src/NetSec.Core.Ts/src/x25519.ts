/**
 * X25519 (RFC 7748 section 5), with a trace of the Montgomery ladder.
 *
 * 1. A different model from curve.ts. The curve is v^2 = u^3 + 486662u^2 + u mod 2^255 - 19, and the
 *    ladder works with the u value only. No point has a y here, and no point addition runs.
 * 2. The steps follow the pseudocode of RFC 7748 section 5, with native bigint.
 * 3. Pure and frozen. Practice use only: bigint math is not constant time, so never use this
 *    with a real secret.
 */

export const P25519 = (1n << 255n) - 19n
/** (486662 - 2) / 4, the constant of the ladder step. */
export const A24 = 121665n
/** The u value of the base point: 9. */
export const BASE_U = 9n

const mod = (v: bigint): bigint => ((v % P25519) + P25519) % P25519

function powMod(base: bigint, exp: bigint): bigint {
  let acc = 1n
  let b = mod(base)
  for (let e = exp; e > 0n; e >>= 1n) {
    if (e & 1n) acc = (acc * b) % P25519
    b = (b * b) % P25519
  }
  return acc
}
/** 1 / v mod p, by Fermat: v^(p - 2). The inverse of 0 is 0 here, as RFC 7748 needs. */
const invert = (v: bigint): bigint => powMod(v, P25519 - 2n)

export class X25519Error extends Error {
  readonly code: 'X25519_LENGTH' | 'X25519_ALL_ZERO'
  constructor(code: 'X25519_LENGTH' | 'X25519_ALL_ZERO', message: string) {
    super(message)
    this.name = 'X25519Error'
    this.code = code
  }
}

function need32(b: ArrayLike<number>, what: string): void {
  if (b.length !== 32) throw new X25519Error('X25519_LENGTH', `The ${what} must be 32 bytes.`)
}

/** 32 little-endian bytes to a number. */
export function decodeLittleEndian(b: ArrayLike<number>): bigint {
  let v = 0n
  for (let i = b.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(b[i])
  return v
}
/** A number to 32 little-endian bytes. */
export function encodeU(u: bigint): Uint8Array {
  const out = new Uint8Array(32)
  let v = mod(u)
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

/** The 3 changes that clamping makes to the secret bytes (RFC 7748 section 5, decodeScalar25519). */
export interface Clamp {
  readonly before: Uint8Array
  readonly after: Uint8Array
  /** The scalar as a number, after the clamp. */
  readonly k: bigint
}

/**
 * Clamp the secret: clear the low 3 bits (so k is a multiple of 8, the cofactor), clear the top bit,
 * and set bit 254 (so every secret has the same length in bits).
 */
export function clamp(secret: ArrayLike<number>): Clamp {
  need32(secret, 'secret')
  const before = Uint8Array.from(secret)
  const after = Uint8Array.from(secret)
  after[0] &= 248
  after[31] &= 127
  after[31] |= 64
  return Object.freeze({ before, after, k: decodeLittleEndian(after) })
}

/** The u value from 32 bytes: the top bit is ignored (RFC 7748 section 5, decodeUCoordinate). */
export function decodeU(u: ArrayLike<number>): bigint {
  need32(u, 'u value')
  const copy = Uint8Array.from(u)
  copy[31] &= 127
  return mod(decodeLittleEndian(copy))
}

/** One step of the ladder: one bit of k, from bit 254 down to bit 0. */
export interface LadderRow {
  readonly bit: number
  readonly kBit: 0 | 1
  /** True when this step swaps the 2 working points before it does the math. */
  readonly swap: boolean
  /** The 2 working points after the step, each as x and z (the u value is x / z). */
  readonly x2: bigint
  readonly z2: bigint
  readonly x3: bigint
  readonly z3: bigint
}

export interface LadderWalk {
  readonly clamp: Clamp
  /** The u value that goes in. */
  readonly u: bigint
  readonly rows: readonly LadderRow[]
  /** True when a last swap runs after the loop. */
  readonly finalSwap: boolean
  /** x2 and z2 after the loop and the last swap. */
  readonly x2: bigint
  readonly z2: bigint
  /** The u value that comes out: x2 / z2. */
  readonly result: bigint
  readonly output: Uint8Array
}

/** X25519(secret, u), with every ladder step (RFC 7748 section 5). */
export function ladderWalk(secret: ArrayLike<number>, uBytes: ArrayLike<number>): LadderWalk {
  const c = clamp(secret)
  const x1 = decodeU(uBytes)
  let x2 = 1n
  let z2 = 0n
  let x3 = x1
  let z3 = 1n
  let swap = 0n
  const rows: LadderRow[] = []
  for (let t = 254; t >= 0; t -= 1) {
    const kt = (c.k >> BigInt(t)) & 1n
    swap ^= kt
    const did = swap === 1n
    if (did) {
      ;[x2, x3] = [x3, x2]
      ;[z2, z3] = [z3, z2]
    }
    swap = kt

    const A = mod(x2 + z2)
    const AA = mod(A * A)
    const B = mod(x2 - z2)
    const BB = mod(B * B)
    const E = mod(AA - BB)
    const C = mod(x3 + z3)
    const D = mod(x3 - z3)
    const DA = mod(D * A)
    const CB = mod(C * B)
    x3 = mod((DA + CB) ** 2n)
    z3 = mod(x1 * mod((DA - CB) ** 2n))
    x2 = mod(AA * BB)
    z2 = mod(E * mod(AA + A24 * E))
    rows.push(Object.freeze({ bit: t, kBit: kt === 1n ? 1 : 0, swap: did, x2, z2, x3, z3 }))
  }
  const finalSwap = swap === 1n
  if (finalSwap) {
    ;[x2, x3] = [x3, x2]
    ;[z2, z3] = [z3, z2]
  }
  const result = mod(x2 * invert(z2))
  return Object.freeze({ clamp: c, u: x1, rows: Object.freeze(rows), finalSwap, x2, z2, result, output: encodeU(result) })
}

/** X25519(secret, u): 32 bytes out. */
export const x25519 = (secret: ArrayLike<number>, u: ArrayLike<number>): Uint8Array => ladderWalk(secret, u).output

/** The public value of a secret: X25519(secret, 9). */
export const x25519Public = (secret: ArrayLike<number>): Uint8Array => x25519(secret, encodeU(BASE_U))

/** What one side holds and makes. */
export interface X25519SideWalk {
  readonly secret: Uint8Array
  readonly public: LadderWalk
  readonly shared: LadderWalk
}

export interface X25519Exchange {
  readonly client: X25519SideWalk
  readonly server: X25519SideWalk
  /** The 32 bytes both sides now hold. */
  readonly secret: Uint8Array
}

/** A full exchange. It refuses an all-zero result, as RFC 7748 section 6.1 says a caller may. */
export function x25519Exchange(clientSecret: ArrayLike<number>, serverSecret: ArrayLike<number>): X25519Exchange {
  const base = encodeU(BASE_U)
  const cp = ladderWalk(clientSecret, base)
  const sp = ladderWalk(serverSecret, base)
  const client: X25519SideWalk = Object.freeze({ secret: Uint8Array.from(clientSecret), public: cp, shared: ladderWalk(clientSecret, sp.output) })
  const server: X25519SideWalk = Object.freeze({ secret: Uint8Array.from(serverSecret), public: sp, shared: ladderWalk(serverSecret, cp.output) })
  if (client.shared.output.every((b) => b === 0)) {
    throw new X25519Error('X25519_ALL_ZERO', 'The shared value is all zero bytes. The other public value is a bad point.')
  }
  return Object.freeze({ client, server, secret: client.shared.output })
}
