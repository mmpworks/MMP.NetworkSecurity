// Checks for gcm.ts. Each check uses a source that shares no code with it:
// 1. NIST CAVP gcmtestvectors (acceptance/vectors/gcm-cavp.nsv): every seal record, and every record marked FAIL.
// 2. node:crypto AES-GCM on random inputs, with IVs of 12 bytes and of other lengths.
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createCipheriv, randomBytes } from 'node:crypto'
import { bytesToHex, hexToBytes } from '../src/hash.ts'
import { GcmError, gcmDecrypt, gcmEncrypt, gcmOpenParts, gcmParts, ghash } from '../src/gcm.ts'

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

const codeOf = (fn: () => unknown): string => {
  try {
    fn()
  } catch (e) {
    return e instanceof GcmError ? e.code : `other: ${String(e)}`
  }
  return 'no error'
}

describe('AES-GCM against NIST CAVP', () => {
  const seal = nsvRecords('gcm-cavp.nsv', 'gcm-seal')
  const fail = nsvRecords('gcm-cavp.nsv', 'gcm-open-fail')

  test('the vector file holds 300 seal records and 150 FAIL records, with 3 key sizes', () => {
    assert.equal(seal.length, 300)
    assert.equal(fail.length, 150)
    assert.deepEqual([...new Set(seal.map((r) => r.key.length / 2))].sort(), [16, 24, 32])
  })

  test('encrypt: every seal record gives the ciphertext and the tag of the file', () => {
    for (const r of seal) {
      const out = gcmEncrypt(hexToBytes(r.key), hexToBytes(r.iv), hexToBytes(r.plaintext), hexToBytes(r.aad))
      assert.equal(bytesToHex(out.ciphertext), r.ciphertext)
      assert.equal(bytesToHex(out.tag), r.tag)
    }
  })

  test('decrypt: every seal record gives the plaintext back', () => {
    for (const r of seal) {
      const plain = gcmDecrypt(hexToBytes(r.key), hexToBytes(r.iv), hexToBytes(r.ciphertext), hexToBytes(r.tag), hexToBytes(r.aad))
      assert.equal(bytesToHex(plain), r.plaintext)
    }
  })

  test('decrypt: every record marked FAIL throws GCM_TAG_MISMATCH', () => {
    for (const r of fail) {
      const code = codeOf(() => gcmDecrypt(hexToBytes(r.key), hexToBytes(r.iv), hexToBytes(r.ciphertext), hexToBytes(r.tag), hexToBytes(r.aad)))
      assert.equal(code, 'GCM_TAG_MISMATCH')
    }
  })
})

describe('AES-GCM against node:crypto', () => {
  const nodeSeal = (key: Buffer, iv: Buffer, plain: Buffer, aad: Buffer): { ciphertext: string; tag: string } => {
    const c = createCipheriv(`aes-${key.length * 8}-gcm` as 'aes-128-gcm', key, iv)
    c.setAAD(aad)
    const ciphertext = Buffer.concat([c.update(plain), c.final()])
    return { ciphertext: ciphertext.toString('hex'), tag: c.getAuthTag().toString('hex') }
  }

  test('random keys, IVs of 12 bytes, texts and AAD of 0 to 70 bytes', () => {
    let n = 0
    for (const keyLen of [16, 24, 32]) {
      for (const len of [0, 1, 15, 16, 17, 31, 32, 33, 70]) {
        const key = randomBytes(keyLen)
        const iv = randomBytes(12)
        const plain = randomBytes(len)
        const aad = randomBytes((len * 7) % 41)
        const want = nodeSeal(key, iv, plain, aad)
        const got = gcmEncrypt(key, iv, plain, aad)
        assert.equal(bytesToHex(got.ciphertext), want.ciphertext)
        assert.equal(bytesToHex(got.tag), want.tag)
        assert.equal(bytesToHex(gcmDecrypt(key, iv, got.ciphertext, got.tag, aad)), plain.toString('hex'))
        n += 1
      }
    }
    assert.equal(n, 27)
  })

  test('IVs that are not 12 bytes go through GHASH and still match', () => {
    for (const ivLen of [1, 8, 13, 16, 20, 60]) {
      const key = randomBytes(16)
      const iv = randomBytes(ivLen)
      const plain = randomBytes(40)
      const aad = randomBytes(9)
      const want = nodeSeal(key, iv, plain, aad)
      const got = gcmEncrypt(key, iv, plain, aad)
      assert.equal(bytesToHex(got.ciphertext), want.ciphertext, `IV of ${ivLen} bytes`)
      assert.equal(bytesToHex(got.tag), want.tag, `IV of ${ivLen} bytes`)
    }
  })

  test('one changed bit in the ciphertext, the tag, the AAD or the key throws GCM_TAG_MISMATCH', () => {
    const key = randomBytes(16)
    const iv = randomBytes(12)
    const plain = randomBytes(33)
    const aad = randomBytes(13)
    const { ciphertext, tag } = gcmEncrypt(key, iv, plain, aad)
    const flip = (b: Uint8Array, at: number): Uint8Array => Uint8Array.from(b, (x, i) => (i === at ? x ^ 1 : x))
    assert.equal(codeOf(() => gcmDecrypt(key, iv, flip(ciphertext, 20), tag, aad)), 'GCM_TAG_MISMATCH')
    assert.equal(codeOf(() => gcmDecrypt(key, iv, ciphertext, flip(tag, 0), aad)), 'GCM_TAG_MISMATCH')
    assert.equal(codeOf(() => gcmDecrypt(key, iv, ciphertext, tag, flip(aad, 12))), 'GCM_TAG_MISMATCH')
    assert.equal(codeOf(() => gcmDecrypt(flip(key, 3), iv, ciphertext, tag, aad)), 'GCM_TAG_MISMATCH')
    assert.equal(codeOf(() => gcmDecrypt(key, iv, ciphertext, tag, aad)), 'no error')
  })

  test('a tag that is not 16 bytes and an empty IV have their own codes', () => {
    const key = randomBytes(16)
    assert.equal(codeOf(() => gcmDecrypt(key, randomBytes(12), [], randomBytes(12))), 'GCM_TAG_LENGTH')
    assert.equal(codeOf(() => gcmEncrypt(key, [], [1, 2, 3])), 'GCM_IV_LENGTH')
  })
})

describe('the parts of one GCM run', () => {
  const key = hexToBytes('000102030405060708090a0b0c0d0e0f')
  const iv = hexToBytes('101112131415161718191a1b')
  const plain = Uint8Array.from({ length: 20 }, (_, i) => i)
  const aad = Uint8Array.from([9, 8, 7])
  const p = gcmParts(key, iv, plain, aad)

  test('H is the AES encryption of 16 zero bytes (node:crypto ECB)', () => {
    const ecb = createCipheriv('aes-128-ecb', key, null)
    ecb.setAutoPadding(false)
    assert.equal(bytesToHex(p.h), Buffer.concat([ecb.update(Buffer.alloc(16)), ecb.final()]).toString('hex'))
  })
  test('J0 is the IV and then the counter 1', () => {
    assert.equal(bytesToHex(p.j0), `${bytesToHex(iv)}00000001`)
  })
  test('output = input XOR key stream, and tag = GHASH XOR AES(J0)', () => {
    assert.deepEqual(Array.from(p.output), Array.from(plain, (x, i) => x ^ p.keystream[i]))
    assert.deepEqual(Array.from(p.tag), Array.from(p.ghash, (x, i) => x ^ p.tagMask[i]))
    assert.equal(bytesToHex(ghash(p.h, aad, p.output)), bytesToHex(p.ghash))
  })
  test('the parts of the decryption are the same, with the plaintext as output', () => {
    const q = gcmOpenParts(key, iv, p.output, aad)
    assert.equal(bytesToHex(q.output), bytesToHex(plain))
    assert.equal(bytesToHex(q.tag), bytesToHex(p.tag))
    assert.equal(bytesToHex(q.keystream), bytesToHex(p.keystream))
  })
})
