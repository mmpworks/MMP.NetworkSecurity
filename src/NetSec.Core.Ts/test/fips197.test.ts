// The anchor: every intermediate value FIPS 197 publishes for the three key sizes, checked against the walk.
// The expected values come from test/fips197/fips197-vectors.json, which extract.py transcribed from the NIST PDFs.
// This file shares no code with the engine: it reads the walk's output and compares hex strings.
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { walkKeyExpansion, walkEncrypt, walkDecrypt } from '../src/index.ts'
import type { AesStep, AesStepKind } from '../src/index.ts'

interface ExpansionRow { i: number; temp: string; afterRotWord?: string; afterSubWord?: string; rcon?: string; afterXorWithRcon?: string; wBack: string; w: string }
interface Expansion { nk: number; key: string; keyWords: string[]; rows: ExpansionRow[]; words: string[] }
interface TraceValue { round: number; tag: string; hex: string }
interface CipherExample { plaintext: string; key: string; encrypt: TraceValue[]; decrypt: TraceValue[] }
interface Vectors { keyExpansion: Record<string, Expansion>; cipher: Record<string, CipherExample> }

const vectors: Vectors = JSON.parse(readFileSync(new URL('./fips197/fips197-vectors.json', import.meta.url), 'utf8'))
const ROUNDS: Record<string, number> = { '128': 10, '192': 12, '256': 14 }

const hex = (bytes: ArrayLike<number> | null): string | null =>
  bytes === null ? null : Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
const bytes = (h: string): number[] => Array.from({ length: h.length / 2 }, (_, i) => parseInt(h.slice(2 * i, 2 * i + 2), 16))

/** The one step of `kind` in `round`. The walk must hold one and only one. */
function stepOf(steps: readonly AesStep[], kind: AesStepKind, round: number): AesStep {
  const found = steps.filter(s => s.kind === kind && s.round === round)
  assert.equal(found.length, 1, `one ${kind} step in round ${round}`)
  return found[0]
}

for (const size of ['128', '192', '256']) {
  const e = vectors.keyExpansion[size]
  describe(`FIPS 197 A (AES-${size} key expansion, ${e.words.length} words)`, () => {
    const walk = walkKeyExpansion(bytes(e.key))
    test('one step per word', () => assert.equal(walk.length, e.words.length))
    e.words.forEach((w, i) => {
      test(`w${i} = ${w}`, () => {
        const step = walk[i]
        assert.equal(step.index, i)
        assert.equal(hex(step.word), w)
        assert.equal(step.divisor, e.nk)
        if (i < e.nk) {
          for (const stage of [step.previous, step.rotated, step.substituted, step.rcon, step.afterRcon, step.keyBack]) assert.equal(stage, null)
          return
        }
        const row = e.rows.find(r => r.i === i)!
        assert.equal(step.quotient, Math.floor(i / e.nk))
        assert.equal(step.remainder, i % e.nk)
        assert.equal(hex(step.previous), row.temp)
        assert.equal(hex(step.rotated), row.afterRotWord ?? null)
        assert.equal(hex(step.substituted), row.afterSubWord ?? null)
        assert.equal(hex(step.rcon), row.rcon ?? null)
        assert.equal(hex(step.afterRcon), row.afterXorWithRcon ?? null)
        assert.equal(hex(step.keyBack), row.wBack)
      })
    })
  })
}

const ENCRYPT_TAGS: Record<string, (steps: readonly AesStep[], r: number) => string | null> = {
  start: (s, r) => hex(stepOf(s, 'SubBytes', r).before),
  s_box: (s, r) => hex(stepOf(s, 'SubBytes', r).after),
  s_row: (s, r) => hex(stepOf(s, 'ShiftRows', r).after),
  m_col: (s, r) => hex(stepOf(s, 'MixColumns', r).after),
  k_sch: (s, r) => hex(stepOf(s, 'AddRoundKey', r).roundKey),
}

// FIPS numbers the inverse cipher's rounds 0 to Nr in the order they run. The walk, like the C# engine, numbers each step
// by the number of the round key its round uses, so FIPS round r is walk round Nr - r. FIPS round 0 is the first AddRoundKey (key Nr).
const DECRYPT_TAGS: Record<string, (steps: readonly AesStep[], r: number, nr: number) => string | null> = {
  istart: (s, r, nr) => hex(stepOf(s, 'InvShiftRows', nr - r).before),
  is_row: (s, r, nr) => hex(stepOf(s, 'InvShiftRows', nr - r).after),
  is_box: (s, r, nr) => hex(stepOf(s, 'InvSubBytes', nr - r).after),
  ik_sch: (s, r, nr) => hex(stepOf(s, 'AddRoundKey', nr - r).roundKey),
  ik_add: (s, r, nr) => hex(stepOf(s, 'AddRoundKey', nr - r).after),
}

for (const size of ['128', '192', '256']) {
  const c = vectors.cipher[size]
  const nr = ROUNDS[size]
  describe(`FIPS 197 C (AES-${size} cipher, ${c.encrypt.length} values)`, () => {
    const walk = walkEncrypt(bytes(c.key), bytes(c.plaintext))
    test('step order is FIPS Algorithm 1', () => {
      const order: string[] = ['AddRoundKey:0']
      for (let r = 1; r <= nr; r++) {
        order.push(`SubBytes:${r}`, `ShiftRows:${r}`)
        if (r < nr) order.push(`MixColumns:${r}`)
        order.push(`AddRoundKey:${r}`)
      }
      assert.deepEqual(walk.steps.map(s => `${s.kind}:${s.round}`), order)
      assert.equal(walk.rounds, nr)
    })
    for (const v of c.encrypt) {
      test(`round[${v.round}].${v.tag} = ${v.hex}`, () => {
        if (v.tag === 'input') return assert.equal(hex(walk.input), v.hex)
        if (v.tag === 'output') return assert.equal(hex(walk.output), v.hex)
        assert.equal(ENCRYPT_TAGS[v.tag](walk.steps, v.round), v.hex)
      })
    }
  })
  describe(`FIPS 197 C (AES-${size} inverse cipher, ${c.decrypt.length} values)`, () => {
    const ciphertext = c.decrypt.find(v => v.tag === 'iinput')!.hex
    const walk = walkDecrypt(bytes(c.key), bytes(ciphertext))
    test('step order is FIPS INVCIPHER (section 5.3)', () => {
      const order: string[] = [`AddRoundKey:${nr}`]
      for (let r = nr - 1; r >= 0; r--) {
        order.push(`InvShiftRows:${r}`, `InvSubBytes:${r}`, `AddRoundKey:${r}`)
        if (r > 0) order.push(`InvMixColumns:${r}`)
      }
      assert.deepEqual(walk.steps.map(s => `${s.kind}:${s.round}`), order)
    })
    for (const v of c.decrypt) {
      test(`round[${v.round}].${v.tag} = ${v.hex}`, () => {
        if (v.tag === 'iinput') return assert.equal(hex(walk.input), v.hex)
        if (v.tag === 'ioutput') return assert.equal(hex(walk.output), v.hex)
        assert.equal(DECRYPT_TAGS[v.tag](walk.steps, v.round, nr), v.hex)
      })
    }
  })
}
