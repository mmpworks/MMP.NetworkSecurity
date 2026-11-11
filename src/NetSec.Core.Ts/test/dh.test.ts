// Checks for dh.ts. Each check uses a source that shares no code with dh.ts:
// 1. The RFC 3526 group 14 prime, from acceptance/vectors/dh-group14-rfc3526.nsv.
// 2. The practice exponents, recomputed with node:crypto SHAKE256 from the app's labels.
// 3. The small exchange, by plain repeated multiply (no square-and-multiply).
// 4. Group 14 known answers that OpenSSL 3.5.7 made (acceptance/vectors/dh-group14-openssl.nsv).
// 5. Group 14 with the practice exponents, against node:crypto Diffie-Hellman (OpenSSL).
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createDiffieHellman, createHash } from 'node:crypto'
import {
  GROUP14_GENERATOR,
  GROUP14_PRACTICE,
  GROUP14_PRIME,
  SMALL,
  dhGroup14,
  dhSmall,
  powWalk,
  toBytes,
} from '../src/dh.ts'

const VECTORS = new URL('../../../acceptance/vectors/', import.meta.url)

/** The key = value lines of an .nsv file, in file order. */
function nsv(name: string): Array<[string, string]> {
  return readFileSync(new URL(name, VECTORS), 'utf8')
    .split(/\r?\n/)
    .map((l) => /^([a-z_]+) = ([0-9a-f]+)$/.exec(l.trim()))
    .filter((m): m is RegExpExecArray => m !== null)
    .map((m) => [m[1], m[2]])
}
const big = (hex: string): bigint => BigInt(`0x${hex}`)

describe('group 14 parameters', () => {
  test('the prime and generator match RFC 3526 section 3', () => {
    const v = new Map(nsv('dh-group14-rfc3526.nsv'))
    assert.equal(GROUP14_PRIME, big(v.get('p') ?? ''))
    assert.equal(GROUP14_GENERATOR, big(v.get('g') ?? ''))
    assert.equal(GROUP14_PRIME.toString(2).length, 2048)
  })

  test('the practice exponents are SHAKE256 of the app labels, top bit set', () => {
    for (const side of ['client', 'server'] as const) {
      const h = createHash('shake256', { outputLength: 4 }).update(`MMP.NetworkSecurity DH practice ${side}`).digest()
      h[0] |= 0x80
      assert.equal(GROUP14_PRACTICE[side], big(h.toString('hex')), side)
    }
  })
})

describe('small exchange (p = 467, g = 5)', () => {
  /** g^x mod p by x plain multiplies. Slow and obvious, so it shares no logic with powWalk. */
  const slowPow = (g: bigint, x: bigint, p: bigint): bigint => {
    let acc = 1n
    for (let i = 0n; i < x; i += 1n) acc = (acc * g) % p
    return acc
  }
  const walk = dhSmall()

  test('public values and the secret match plain repeated multiply', () => {
    const A = slowPow(SMALL.generator, SMALL.clientPrivate, SMALL.prime)
    const B = slowPow(SMALL.generator, SMALL.serverPrivate, SMALL.prime)
    assert.equal(walk.client.public.result, A)
    assert.equal(walk.server.public.result, B)
    assert.equal(walk.secret, slowPow(B, SMALL.clientPrivate, SMALL.prime))
    assert.equal(walk.secret, slowPow(A, SMALL.serverPrivate, SMALL.prime))
  })

  test('one row for each exponent bit, top bit first, multiply only on a 1 bit', () => {
    const rows = walk.client.public.rows
    assert.equal(rows.length, SMALL.clientPrivate.toString(2).length)
    assert.deepEqual(
      rows.map((r) => (r.isOne ? '1' : '0')).join(''),
      SMALL.clientPrivate.toString(2),
    )
    for (const r of rows) assert.equal(r.afterMultiply === null, !r.isOne)
  })

  test('the walk is frozen', () => {
    assert.ok(Object.isFrozen(walk))
    assert.ok(Object.isFrozen(walk.client.public.rows))
    assert.ok(Object.isFrozen(walk.client.public.rows[0]))
  })
})

describe('group 14 against OpenSSL 3.5.7 known answers', () => {
  const lines = nsv('dh-group14-openssl.nsv')
  const cases: Array<Record<string, string>> = []
  for (const [k, v] of lines) {
    if (k === 'x_a') cases.push({})
    cases[cases.length - 1][k] = v
  }
  test('the vector file holds 3 cases', () => assert.equal(cases.length, 3))
  cases.forEach((c, n) => {
    test(`case ${n}: g^x_a = y_a, and y_b^x_a = shared`, () => {
      assert.equal(powWalk(GROUP14_GENERATOR, big(c.x_a), GROUP14_PRIME).result, big(c.y_a))
      assert.equal(powWalk(big(c.y_b), big(c.x_a), GROUP14_PRIME).result, big(c.shared))
    })
  })
})

/**
 * b^x mod p, right to left (low bit first). A different method from powWalk,
 * which goes left to right, so a shared mistake is unlikely.
 */
function rtlPow(b: bigint, x: bigint, p: bigint): bigint {
  let acc = 1n
  let sq = b % p
  for (let e = x; e > 0n; e >>= 1n) {
    if (e & 1n) acc = (acc * sq) % p
    sq = (sq * sq) % p
  }
  return acc
}

describe('each row against its own rule', () => {
  // After the square on bit k, the value is b^(2 * (e >> (k + 1))).
  // After the multiply on bit k, it is b^(e >> k).
  const cases: Array<[string, bigint, bigint, bigint]> = [
    ['small, client public', SMALL.generator, SMALL.clientPrivate, SMALL.prime],
    ['small, server shared', dhSmall().client.public.result, SMALL.serverPrivate, SMALL.prime],
    ['group 14, client public', GROUP14_GENERATOR, GROUP14_PRACTICE.client, GROUP14_PRIME],
    ['group 14, server shared', dhGroup14().client.public.result, GROUP14_PRACTICE.server, GROUP14_PRIME],
  ]
  for (const [name, b, e, p] of cases) {
    test(name, () => {
      const walk = powWalk(b, e, p)
      walk.rows.forEach((r, n) => {
        assert.equal(r.bit, walk.rows.length - 1 - n, `row ${n} bit`)
        assert.equal(r.afterSquare, rtlPow(b, 2n * (e >> BigInt(r.bit + 1)), p), `row ${n} square`)
        if (r.isOne) assert.equal(r.afterMultiply, rtlPow(b, e >> BigInt(r.bit), p), `row ${n} multiply`)
      })
    })
  }
})

describe('edges and errors', () => {
  test('exponent 1 gives one row with a multiply', () => {
    const w = powWalk(5n, 1n, 467n)
    assert.equal(w.rows.length, 1)
    assert.equal(w.rows[0].isOne, true)
    assert.equal(w.result, 5n)
  })
  test('a base of p or more, or below 0, is reduced first', () => {
    assert.equal(powWalk(467n + 5n, 153n, 467n).result, dhSmall().client.public.result)
    assert.equal(powWalk(5n - 467n, 153n, 467n).result, dhSmall().client.public.result)
    assert.equal(powWalk(0n, 7n, 467n).result, 0n)
  })
  test('bad input throws a coded error', () => {
    assert.throws(() => powWalk(5n, 0n, 467n), { code: 'DH_BAD_EXPONENT' })
    assert.throws(() => powWalk(5n, 3n, 2n), { code: 'DH_BAD_PRIME' })
    assert.throws(() => toBytes(-1n), { code: 'DH_BAD_VALUE' })
  })
  test('toBytes pads to a width and keeps a leading zero byte off', () => {
    assert.deepEqual(Array.from(toBytes(0x1ffn)), [0x01, 0xff])
    assert.deepEqual(Array.from(toBytes(0x1ffn, 4)), [0, 0, 0x01, 0xff])
    assert.equal(toBytes(GROUP14_PRIME).length, 256)
  })
  test('the whole walk is frozen', () => {
    const w = dhGroup14()
    for (const o of [w, w.client, w.server, w.client.public, w.client.shared, w.server.public, w.server.shared]) {
      assert.ok(Object.isFrozen(o))
    }
    assert.ok(w.client.public.rows.every((r) => Object.isFrozen(r)))
    assert.equal(w.realExponentBits, 512)
  })
})

describe('group 14 practice exchange against node:crypto', () => {
  test('both public values and the secret match OpenSSL through node:crypto', () => {
    const walk = dhGroup14()
    const p = Buffer.from(toBytes(GROUP14_PRIME))
    const g = Buffer.from(toBytes(GROUP14_GENERATOR))
    const side = (x: bigint) => {
      const dh = createDiffieHellman(p, g)
      dh.setPrivateKey(Buffer.from(toBytes(x)))
      dh.generateKeys()
      return dh
    }
    const client = side(GROUP14_PRACTICE.client)
    const server = side(GROUP14_PRACTICE.server)
    assert.equal(walk.client.public.result, big(client.getPublicKey('hex')))
    assert.equal(walk.server.public.result, big(server.getPublicKey('hex')))
    assert.equal(walk.secret, big(client.computeSecret(server.getPublicKey()).toString('hex')))
    assert.equal(walk.client.public.rows.length, 32)
  })
})
