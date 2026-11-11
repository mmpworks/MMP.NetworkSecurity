/**
 * Diffie-Hellman walks: g^x mod p, one exponent bit at a time.
 *
 * TypeScript port of `src/NetSec.Core/Labs/DhWalks.cs` (branch chore/pin-vue-vite-328).
 * 1. Same two exchanges as the app: the small prime 467 (g = 5, exponents 153 and 197),
 *    and RFC 3526 group 14 with 32-bit practice exponents.
 * 2. Left-to-right square and multiply. One row for each exponent bit, top bit first.
 * 3. Pure and frozen, like walk.ts. Native bigint, so no limb math.
 * 4. Practice values only. Nothing here is a secret, and nothing here is constant time.
 */

/** One bit of a modular power: square, then multiply when the bit is 1. */
export interface DhPowRow {
  /** Position of the bit, 0 at the low end. */
  readonly bit: number
  readonly isOne: boolean
  readonly afterSquare: bigint
  /** Null when the bit is 0: no multiply runs. */
  readonly afterMultiply: bigint | null
}

/** base^exponent mod p, row by row. */
export interface DhPowWalk {
  readonly base: bigint
  readonly exponent: bigint
  readonly result: bigint
  readonly rows: readonly DhPowRow[]
}

/** What one side holds and makes. */
export interface DhSideWalk {
  readonly private: bigint
  /** g^private mod p: the value this side sends. */
  readonly public: DhPowWalk
  /** peer public^private mod p: the shared secret this side makes. */
  readonly shared: DhPowWalk
}

export type DhGroupName = 'small' | 'group14'

export interface DhWalk {
  readonly group: DhGroupName
  readonly prime: bigint
  readonly generator: bigint
  readonly client: DhSideWalk
  readonly server: DhSideWalk
  /** The secret both sides now hold. Equal to client.shared.result and server.shared.result. */
  readonly secret: bigint
}

export class DhError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = 'DhError'
    this.code = code
  }
}

/** A small safe prime, 467 = 2 x 233 + 1, with 5 a primitive root, so every number fits in a sentence. */
export const SMALL = Object.freeze({ prime: 467n, generator: 5n, clientPrivate: 153n, serverPrivate: 197n })

/** RFC 3526 section 3: the 2048-bit MODP group, id 14. g = 2. Copied from acceptance/vectors/dh-group14-rfc3526.nsv by script. */
export const GROUP14_PRIME = BigInt(
  '0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff',
)
export const GROUP14_GENERATOR = 2n

/**
 * 32-bit public practice exponents, as the app makes them: SHAKE256 of
 * "MMP.NetworkSecurity DH practice <side>", first 4 bytes, top bit set.
 * The test recomputes them with node:crypto.
 */
export const GROUP14_PRACTICE = Object.freeze({ client: 0xe5494e98n, server: 0xbf4f55efn })

/** Left-to-right square and multiply. The rows read the exponent from its top set bit down to bit 0. */
export function powWalk(base: bigint, exponent: bigint, p: bigint): DhPowWalk {
  if (p < 3n) throw new DhError('DH_BAD_PRIME', 'The modulus must be 3 or more.')
  if (exponent < 1n) throw new DhError('DH_BAD_EXPONENT', 'The exponent must be 1 or more.')
  const b = ((base % p) + p) % p
  let acc = 1n
  const rows: DhPowRow[] = []
  for (let bit = exponent.toString(2).length - 1; bit >= 0; bit -= 1) {
    const isOne = ((exponent >> BigInt(bit)) & 1n) === 1n
    acc = (acc * acc) % p
    const afterSquare = acc
    let afterMultiply: bigint | null = null
    if (isOne) {
      acc = (acc * b) % p
      afterMultiply = acc
    }
    rows.push(Object.freeze({ bit, isOne, afterSquare, afterMultiply }))
  }
  return Object.freeze({ base: b, exponent, result: acc, rows: Object.freeze(rows) })
}

function exchange(group: DhGroupName, p: bigint, g: bigint, a: bigint, b: bigint): DhWalk {
  const clientPublic = powWalk(g, a, p)
  const serverPublic = powWalk(g, b, p)
  const client: DhSideWalk = Object.freeze({
    private: a,
    public: clientPublic,
    shared: powWalk(serverPublic.result, a, p),
  })
  const server: DhSideWalk = Object.freeze({
    private: b,
    public: serverPublic,
    shared: powWalk(clientPublic.result, b, p),
  })
  if (client.shared.result !== server.shared.result) {
    throw new DhError('DH_WALK_DIVERGED', 'The two sides made different secrets.')
  }
  return Object.freeze({ group, prime: p, generator: g, client, server, secret: client.shared.result })
}

/** The small exchange: p = 467, g = 5, private values 153 and 197. */
export function dhSmall(): DhWalk {
  return exchange('small', SMALL.prime, SMALL.generator, SMALL.clientPrivate, SMALL.serverPrivate)
}

/** RFC 3526 group 14 with the 32-bit practice exponents. */
export function dhGroup14(): DhWalk {
  return exchange('group14', GROUP14_PRIME, GROUP14_GENERATOR, GROUP14_PRACTICE.client, GROUP14_PRACTICE.server)
}

/** A bigint as big-endian bytes, left-padded to `width` bytes when given. */
export function toBytes(value: bigint, width = 0): Uint8Array {
  let hex = value.toString(16)
  if (hex.length % 2 === 1) hex = `0${hex}`
  const n = Math.max(width, hex.length / 2)
  const out = new Uint8Array(n)
  for (let i = 0; i < hex.length / 2; i += 1) out[n - hex.length / 2 + i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16)
  return out
}
