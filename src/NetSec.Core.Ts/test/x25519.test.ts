// Checks for hash.ts and x25519.ts. Each check uses a source that shares no code with them:
// 1. SHA-256, HMAC and HKDF: node:crypto on random inputs, and RFC 5869 appendix A (acceptance/vectors).
// 2. X25519: RFC 7748 sections 5.2 and 6.1 (acceptance/vectors), and node:crypto X25519 on random keys.
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, hkdfSync, randomBytes } from 'node:crypto'
import { bytesToHex, hexToBytes, hkdfExpand, hkdfExtract, hmacSha256, sha256 } from '../src/hash.ts'
import { BASE_U, clamp, encodeU, ladderWalk, x25519, x25519Exchange, x25519Public } from '../src/x25519.ts'

const VECTORS = new URL('../../../acceptance/vectors/', import.meta.url)

/** The records of one [section] of an .nsv file: each blank line starts a new record. */
function nsvRecords(name: string, section: string): Array<Record<string, string>> {
  const text = readFileSync(new URL(name, VECTORS), 'utf8')
  const start = text.indexOf(`[${section}]`)
  const end = text.indexOf('\n[', start + 1)
  const body = text.slice(start, end === -1 ? undefined : end)
  const out: Array<Record<string, string>> = []
  let cur: Record<string, string> | null = null
  for (const raw of body.split(/\r?\n/)) {
    const m = /^([a-z_0-9]+) = ?(.*)$/.exec(raw.trim())
    if (!m) {
      cur = null
      continue
    }
    if (!cur) {
      cur = {}
      out.push(cur)
    }
    cur[m[1]] = m[2]
  }
  return out
}

describe('SHA-256 and HMAC against node:crypto', () => {
  for (const len of [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000]) {
    test(`sha256 of ${len} random bytes`, () => {
      const data = randomBytes(len)
      assert.equal(bytesToHex(sha256(data)), createHash('sha256').update(data).digest('hex'))
    })
  }
  for (const keyLen of [0, 16, 32, 64, 65, 200]) {
    test(`hmac with a ${keyLen}-byte key`, () => {
      const key = randomBytes(keyLen)
      const data = randomBytes(77)
      assert.equal(bytesToHex(hmacSha256(key, data)), createHmac('sha256', key).update(data).digest('hex'))
    })
  }
})

describe('HKDF', () => {
  const cases = nsvRecords('hkdf-rfc5869.nsv', 'hkdf-sha256')
  test('the vector file holds 3 SHA-256 cases', () => assert.equal(cases.length, 3))
  for (const c of cases) {
    test(`RFC 5869 case ${c.case}: PRK and OKM`, () => {
      const prk = hkdfExtract(hexToBytes(c.salt), hexToBytes(c.ikm))
      assert.equal(bytesToHex(prk), c.prk)
      assert.equal(bytesToHex(hkdfExpand(prk, hexToBytes(c.info), Number(c.length))), c.okm)
    })
  }
  test('extract then expand matches node:crypto hkdfSync on random input', () => {
    for (let n = 0; n < 20; n += 1) {
      const ikm = randomBytes(32)
      const salt = randomBytes(n)
      const info = randomBytes(2 * n)
      const len = 1 + 7 * n
      const mine = hkdfExpand(hkdfExtract(salt, ikm), info, len)
      assert.equal(bytesToHex(mine), Buffer.from(hkdfSync('sha256', ikm, salt, info, len)).toString('hex'))
    }
  })
})

describe('X25519 against RFC 7748', () => {
  for (const c of nsvRecords('x25519-rfc7748.nsv', 'x25519-scalarmult')) {
    test(`section 5.2: scalar ${c.scalar.slice(0, 8)}…`, () => {
      assert.equal(bytesToHex(x25519(hexToBytes(c.scalar), hexToBytes(c.u))), c.out)
    })
  }
  for (const c of nsvRecords('x25519-rfc7748.nsv', 'x25519-iterated')) {
    test(`section 5.2: ${c.iterations} iteration(s)`, () => {
      let k = hexToBytes(c.k_start)
      let u = hexToBytes(c.u_start)
      for (let i = 0; i < Number(c.iterations); i += 1) {
        const next = x25519(k, u)
        u = k
        k = next
      }
      assert.equal(bytesToHex(k), c.out)
    })
  }
  const dh = nsvRecords('x25519-rfc7748.nsv', 'x25519-dh')[0]
  test('section 6.1: both public values and the shared secret', () => {
    assert.equal(bytesToHex(x25519Public(hexToBytes(dh.a))), dh.a_pub)
    assert.equal(bytesToHex(x25519Public(hexToBytes(dh.b))), dh.b_pub)
    const ex = x25519Exchange(hexToBytes(dh.a), hexToBytes(dh.b))
    assert.equal(bytesToHex(ex.secret), dh.k)
    assert.equal(bytesToHex(ex.server.shared.output), dh.k)
  })
})

describe('X25519 against node:crypto', () => {
  // A raw 32-byte X25519 key in the PKCS#8 and SPKI wrappers that node:crypto reads.
  const PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex')
  const SPKI = Buffer.from('302a300506032b656e032100', 'hex')
  const priv = (raw: Uint8Array) => createPrivateKey({ key: Buffer.concat([PKCS8, raw]), format: 'der', type: 'pkcs8' })
  const pub = (raw: Uint8Array) => createPublicKey({ key: Buffer.concat([SPKI, raw]), format: 'der', type: 'spki' })

  for (let n = 0; n < 10; n += 1) {
    test(`random pair ${n}: public value and shared secret`, () => {
      const a = randomBytes(32)
      const b = randomBytes(32)
      const A = x25519Public(a)
      const nodeA = createPublicKey(priv(a)).export({ format: 'der', type: 'spki' }).subarray(SPKI.length)
      assert.equal(bytesToHex(A), nodeA.toString('hex'), `secret ${a.toString('hex')}`)
      const mine = x25519(b, A)
      const theirs = diffieHellman({ privateKey: priv(b), publicKey: pub(A) })
      assert.equal(bytesToHex(mine), theirs.toString('hex'), `secrets ${a.toString('hex')} ${b.toString('hex')}`)
    })
  }
})

describe('the ladder trace', () => {
  const secret = hexToBytes('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
  const walk = ladderWalk(secret, encodeU(BASE_U))

  test('clamp: low 3 bits clear, top bit clear, bit 254 set', () => {
    const c = clamp(secret)
    assert.equal(c.after[0] & 7, 0)
    assert.equal(c.after[31] & 0x80, 0)
    assert.equal(c.after[31] & 0x40, 0x40)
    assert.equal(c.k % 8n, 0n)
    assert.equal(c.k.toString(2).length, 255)
  })
  test('255 rows, bit 254 down to bit 0, and the row bits spell the clamped secret', () => {
    assert.equal(walk.rows.length, 255)
    assert.equal(walk.rows[0].bit, 254)
    assert.equal(walk.rows[254].bit, 0)
    assert.equal(walk.rows.map((r) => r.kBit).join(''), walk.clamp.k.toString(2).padStart(255, '0'))
  })
  test('a step swaps when its bit differs from the bit before it', () => {
    walk.rows.forEach((r, n) => {
      const prev = n === 0 ? 0 : walk.rows[n - 1].kBit
      assert.equal(r.swap, r.kBit !== prev, `row ${n}`)
    })
    assert.equal(walk.finalSwap, walk.rows[254].kBit === 1)
  })
  test('the walk is frozen', () => {
    assert.ok(Object.isFrozen(walk))
    assert.ok(Object.isFrozen(walk.rows))
    assert.ok(Object.isFrozen(walk.rows[0]))
  })
  test('bad input throws a coded error', () => {
    assert.throws(() => x25519(new Uint8Array(31), encodeU(BASE_U)), { code: 'X25519_LENGTH' })
    assert.throws(() => x25519Exchange(secret, secret) && x25519(secret, new Uint8Array(33)), { code: 'X25519_LENGTH' })
  })
})
