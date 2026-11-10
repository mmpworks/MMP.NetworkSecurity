// The second check: random keys and blocks against Node's own AES (OpenSSL), which shares no code with the engine.
// A failure message names the key and block, so a reader can run that pair again.
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { encryptBlock, decryptBlock, walkEncrypt, walkDecrypt } from '../src/index.ts'

const PAIRS = 100
const hex = (b: ArrayLike<number>): string => Buffer.from(Array.from(b)).toString('hex')

function nodeEcb(bits: number, key: Buffer, block: Buffer, decrypt: boolean): string {
  const make = decrypt ? createDecipheriv : createCipheriv
  const c = make(`aes-${bits}-ecb`, key, null).setAutoPadding(false)
  return Buffer.concat([c.update(block), c.final()]).toString('hex')
}

for (const bits of [128, 192, 256]) {
  describe(`AES-${bits} against node:crypto aes-${bits}-ecb, ${PAIRS} random pairs`, () => {
    for (let n = 0; n < PAIRS; n++) {
      const key = randomBytes(bits / 8)
      const block = randomBytes(16)
      test(`pair ${n}: key ${key.toString('hex')} block ${block.toString('hex')}`, () => {
        const expected = nodeEcb(bits, key, block, false)
        const walk = walkEncrypt(key, block)
        assert.equal(hex(walk.output), expected, 'walkEncrypt output')
        assert.equal(hex(encryptBlock(key, block)), expected, 'encryptBlock')
        const back = walkDecrypt(key, Buffer.from(expected, 'hex'))
        assert.equal(hex(back.output), block.toString('hex'), 'walkDecrypt returns the plaintext')
        assert.equal(hex(decryptBlock(key, block)), nodeEcb(bits, key, block, true), 'decryptBlock of a random block')
      })
    }
  })
}
