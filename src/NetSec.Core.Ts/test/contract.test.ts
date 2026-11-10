// The trace contract a browser lesson relies on: frozen output, untouched input, linked steps, and coded errors.
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { walkKeyExpansion, walkEncrypt, walkDecrypt, AesError } from '../src/index.ts'

const KEY_128 = Array.from({ length: 16 }, (_, i) => i)
const BLOCK = Array.from({ length: 16 }, (_, i) => (i * 17) & 0xff)

/** Every object and array reachable from `value` is frozen. */
function assertDeepFrozen(value: unknown, path = 'trace'): void {
  if (value === null || typeof value !== 'object') return
  assert.ok(Object.isFrozen(value), `${path} is frozen`)
  for (const [k, v] of Object.entries(value)) assertDeepFrozen(v, `${path}.${k}`)
}

describe('trace contract', () => {
  test('the three traces are frozen all the way down', () => {
    assertDeepFrozen(walkKeyExpansion(KEY_128), 'keyExpansion')
    assertDeepFrozen(walkEncrypt(KEY_128, BLOCK), 'encrypt')
    assertDeepFrozen(walkDecrypt(KEY_128, BLOCK), 'decrypt')
  })

  test('the walks never change their input', () => {
    const key = Uint8Array.from(KEY_128)
    const block = Uint8Array.from(BLOCK)
    walkKeyExpansion(key)
    walkEncrypt(key, block)
    walkDecrypt(key, block)
    assert.deepEqual(Array.from(key), KEY_128)
    assert.deepEqual(Array.from(block), BLOCK)
  })

  test('each step starts from the state the step before it left', () => {
    for (const walk of [walkEncrypt(KEY_128, BLOCK), walkDecrypt(KEY_128, BLOCK)]) {
      let state = walk.input
      for (const step of walk.steps) {
        assert.deepEqual(step.before, state)
        state = step.after
      }
      assert.deepEqual(walk.output, state)
    }
  })

  test('a round key only on AddRoundKey, and mix terms only on the mix steps', () => {
    for (const walk of [walkEncrypt(KEY_128, BLOCK), walkDecrypt(KEY_128, BLOCK)]) {
      for (const step of walk.steps) {
        assert.equal(step.roundKey !== null, step.kind === 'AddRoundKey', `${step.kind} roundKey`)
        const mix = step.kind === 'MixColumns' || step.kind === 'InvMixColumns'
        assert.equal(step.terms !== null, mix, `${step.kind} terms`)
        if (step.terms) assert.deepEqual(step.terms.map(t => t.result), step.after)
      }
    }
  })

  test('bad lengths and bytes throw an AesError with a stable code', () => {
    const code = (f: () => unknown) => {
      try { f() } catch (e) { assert.ok(e instanceof AesError); return e.code }
      assert.fail('no error')
    }
    assert.equal(code(() => walkKeyExpansion(new Array(15).fill(0))), 'AES_KEY_LENGTH')
    assert.equal(code(() => walkEncrypt(KEY_128, new Array(17).fill(0))), 'AES_BLOCK_LENGTH')
    assert.equal(code(() => walkEncrypt(KEY_128, [...BLOCK.slice(1), 256])), 'AES_BYTE')
    assert.equal(code(() => walkDecrypt([...KEY_128.slice(1), 1.5], BLOCK)), 'AES_BYTE')
  })
})
