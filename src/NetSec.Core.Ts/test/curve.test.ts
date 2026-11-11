// Checks for curve.ts. Each check uses a source that shares no code with the add rule in curve.ts:
// 1. The toy curve's points: every (x, y) pair tried here with its own equation check. 18 + O = 19.
// 2. The multiples of G = (5, 1): the table in Paar and Pelzl, Understanding Cryptography, example 9.5.
// 3. The same add and double code on NIST P-256: k·G against node:crypto ECDH (OpenSSL).
// 4. Each row of a walk: against k'·P made by plain repeated addition.
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { createECDH } from 'node:crypto'
import {
  INF,
  TOY_CURVE,
  TOY_G,
  TOY_ORDER,
  TOY_SECRETS,
  add,
  addStep,
  affinePoints,
  checkCurve,
  invMod,
  isOnCurve,
  mul,
  mulWalk,
  negate,
  pt,
  samePoint,
  toyEcdh,
  type Curve,
  type Point,
} from '../src/curve.ts'

const show = (P: Point): string => (P.kind === 'inf' ? 'O' : `(${P.x}, ${P.y})`)

/** k·P by k − 1 plain additions. Slow and obvious. */
function slowMul(c: Curve, k: bigint, P: Point): Point {
  let acc: Point = INF
  for (let i = 0n; i < k; i += 1n) acc = add(c, acc, P)
  return acc
}

describe('toy curve y^2 = x^3 + 2x + 2 mod 17', () => {
  test('it is a real elliptic curve: 4a^3 + 27b^2 is not 0 mod p', () => {
    assert.doesNotThrow(() => checkCurve(TOY_CURVE))
    assert.throws(() => checkCurve({ p: 17n, a: 0n, b: 0n }), { code: 'CURVE_SINGULAR' })
  })

  test('18 points plus O: counted here with a separate equation check', () => {
    const mine: string[] = []
    for (let x = 0; x < 17; x += 1) {
      for (let y = 0; y < 17; y += 1) {
        if ((y * y) % 17 === (x * x * x + 2 * x + 2) % 17) mine.push(`(${x}, ${y})`)
      }
    }
    assert.equal(mine.length, 18)
    assert.deepEqual(affinePoints(TOY_CURVE).map(show), mine)
    assert.equal(BigInt(mine.length) + 1n, TOY_ORDER)
  })

  // Paar and Pelzl, Understanding Cryptography, example 9.5: the multiples of P = (5, 1).
  const PAAR: Array<[number, number]> = [
    [5, 1], [6, 3], [10, 6], [3, 1], [9, 16], [16, 13], [0, 6], [13, 7], [7, 6],
    [7, 11], [13, 10], [0, 11], [16, 4], [9, 1], [3, 16], [10, 11], [6, 14], [5, 16],
  ]
  test('k·G for k = 1 to 18 matches the textbook table, and 19·G = O', () => {
    PAAR.forEach(([x, y], n) => {
      assert.equal(show(mul(TOY_CURVE, BigInt(n + 1), TOY_G)), `(${x}, ${y})`, `${n + 1}·G`)
    })
    assert.equal(show(mul(TOY_CURVE, 19n, TOY_G)), 'O')
  })

  test('the table itself is sound: each point is on the curve, and k·G = −(19 − k)·G', () => {
    PAAR.forEach(([x, y], n) => {
      assert.equal((y * y) % 17, (x * x * x + 2 * x + 2) % 17, `${n + 1}·G on the curve`)
      const [mx, my] = PAAR[17 - n]
      assert.deepEqual([mx, (17 - my) % 17], [x, y], `${n + 1}·G is the negative of ${18 - n}·G`)
    })
  })

  test('G makes every point: 19 is prime, so no small subgroup', () => {
    const seen = new Set<string>()
    for (let k = 1n; k <= TOY_ORDER; k += 1n) seen.add(show(mul(TOY_CURVE, k, TOY_G)))
    assert.equal(seen.size, 19)
  })
})

describe('the add rule', () => {
  const G = TOY_G
  test('each rule is named', () => {
    assert.equal(addStep(TOY_CURVE, INF, G).rule, 'left-is-O')
    assert.equal(addStep(TOY_CURVE, G, INF).rule, 'right-is-O')
    assert.equal(addStep(TOY_CURVE, G, negate(TOY_CURVE, G)).rule, 'opposite')
    assert.equal(addStep(TOY_CURVE, G, G).rule, 'double')
    assert.equal(addStep(TOY_CURVE, G, pt(6n, 3n)).rule, 'add')
  })
  test('the double of G: slope 13, result (6, 3), as in the textbook', () => {
    const s = addStep(TOY_CURVE, G, G)
    // slope = (3·5^2 + 2) / (2·1) = 77 / 2 = 9 · 9 = 81 = 13 mod 17
    assert.equal(s.slopeTop, 9n)
    assert.equal(s.slopeBottom, 2n)
    assert.equal(s.slope, 13n)
    assert.equal(show(s.result), '(6, 3)')
  })
  test('add is the same in each order, and grouping does not matter', () => {
    const pts = [...affinePoints(TOY_CURVE), INF]
    for (const P of pts) {
      for (const Q of pts) {
        assert.ok(samePoint(add(TOY_CURVE, P, Q), add(TOY_CURVE, Q, P)))
        assert.ok(isOnCurve(TOY_CURVE, add(TOY_CURVE, P, Q)))
        assert.ok(
          samePoint(add(TOY_CURVE, add(TOY_CURVE, P, Q), G), add(TOY_CURVE, P, add(TOY_CURVE, Q, G))),
          `(${show(P)} + ${show(Q)}) + G`,
        )
      }
    }
  })
  test('invMod: v · v^-1 = 1 mod 17 for every v', () => {
    for (let v = 1n; v < 17n; v += 1n) assert.equal((v * invMod(v, 17n)) % 17n, 1n)
  })
  test('invMod of 0, and an add of points that are not on the curve, throw a coded error', () => {
    assert.throws(() => invMod(0n, 17n), { code: 'CURVE_NO_INVERSE' })
    assert.throws(() => invMod(34n, 17n), { code: 'CURVE_NO_INVERSE' })
    // Two points off the curve with the same x: the slope needs 1 / 0.
    assert.throws(() => addStep(TOY_CURVE, pt(1n, 5n), pt(1n, 5n + 17n)), { code: 'CURVE_NO_INVERSE' })
  })
})

describe('double-and-add walk', () => {
  for (const k of [1n, 2n, 7n, 13n, 18n, 19n, 20n]) {
    test(`k = ${k}: each row equals the prefix of k times G, by plain repeated add`, () => {
      const walk = mulWalk(TOY_CURVE, k, TOY_G)
      assert.equal(walk.rows.length, k.toString(2).length)
      walk.rows.forEach((r, n) => {
        assert.equal(r.bit, walk.rows.length - 1 - n)
        assert.equal(r.isOne, ((k >> BigInt(r.bit)) & 1n) === 1n)
        assert.equal(r.addP === null, !r.isOne)
        assert.equal(show(r.double.result), show(slowMul(TOY_CURVE, 2n * (k >> BigInt(r.bit + 1)), TOY_G)), `row ${n} double`)
        assert.equal(show(r.after), show(slowMul(TOY_CURVE, k >> BigInt(r.bit), TOY_G)), `row ${n} after`)
      })
      assert.equal(show(walk.result), show(slowMul(TOY_CURVE, k, TOY_G)))
    })
  }
  test('bad input throws a coded error', () => {
    assert.throws(() => mulWalk(TOY_CURVE, 0n, TOY_G), { code: 'CURVE_BAD_SCALAR' })
    assert.throws(() => mulWalk(TOY_CURVE, 3n, pt(1n, 1n)), { code: 'CURVE_NOT_ON_CURVE' })
  })
})

describe('the toy exchange', () => {
  const w = toyEcdh()
  test('A = 13·G, B = 7·G, and both sides get 91·G = 15·G', () => {
    assert.equal(show(w.client.public.result), '(16, 4)')
    assert.equal(show(w.server.public.result), '(0, 6)')
    assert.equal((TOY_SECRETS.client * TOY_SECRETS.server) % TOY_ORDER, 15n)
    assert.equal(show(w.secret), '(3, 16)')
    assert.ok(samePoint(w.client.shared.result, w.server.shared.result))
  })
  test('the whole walk is frozen', () => {
    for (const o of [w, w.client, w.server, w.client.public, w.client.public.rows, w.client.public.rows[0], w.secret]) {
      assert.ok(Object.isFrozen(o))
    }
  })
})

describe('the same code on NIST P-256, against node:crypto', () => {
  // FIPS 186-4, D.1.2.3: curve P-256.
  const P256: Curve = {
    p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
    b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  }
  const G = pt(
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  )
  const hex32 = (v: bigint): string => v.toString(16).padStart(64, '0')

  test('G is on the curve', () => assert.ok(isOnCurve(P256, G)))

  for (const k of [1n, 2n, 3n, 0xdeadbeefn, 0x1f2e3d4c5b6a79880123456789abcdef0fedcba9876543210011223344556677n]) {
    test(`k = ${k.toString(16).slice(0, 12)}…: k·G matches the node:crypto public key`, () => {
      const ecdh = createECDH('prime256v1')
      ecdh.setPrivateKey(Buffer.from(hex32(k), 'hex'))
      const pub = ecdh.getPublicKey('hex', 'uncompressed')
      const mine = mul(P256, k, G)
      assert.equal(mine.kind, 'pt')
      if (mine.kind === 'pt') assert.equal(`04${hex32(mine.x)}${hex32(mine.y)}`, pub)
    })
  }

  test('a full exchange: both shared x values match node:crypto', () => {
    const a = 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20n
    const b = 0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40n
    const node = (x: bigint) => {
      const e = createECDH('prime256v1')
      e.setPrivateKey(Buffer.from(hex32(x), 'hex'))
      return e
    }
    const A = mul(P256, a, G)
    const shared = mul(P256, b, A)
    const expected = node(b).computeSecret(node(a).getPublicKey()).toString('hex')
    assert.equal(shared.kind === 'pt' ? hex32(shared.x) : '', expected)
  })
})
