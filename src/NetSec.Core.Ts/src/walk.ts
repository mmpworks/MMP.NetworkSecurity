// The walk path: every FIPS 197 operation as its own step, with the bytes it took in and gave out.
// It mirrors AesKey.Walk.cs. The walk runs SubBytes and ShiftRows apart, and builds each mixed byte from its terms,
// so the round order lives in two places. Each walk checks its result against the real path (cipher.ts)
// and throws AES_WALK_DIVERGED on a difference.
import { AesError, frozen, readBlock, type Bytes } from './bytes.ts'
import {
  INVERSE_MIX_ROW, INVERSE_SHIFT_ROWS_MAP, MIX_ROW, SHIFT_ROWS_MAP,
  decryptWith, encryptWith, expandKey, inverseMixColumns, mixColumns, move, roundKeyOf, rotWord, subWord, substitute, wordOf, xorBytes,
  type KeySchedule,
} from './cipher.ts'
import { INVERSE_SBOX, SBOX, xtime } from './field.ts'

export type AesStepKind = 'AddRoundKey' | 'SubBytes' | 'ShiftRows' | 'MixColumns' | 'InvShiftRows' | 'InvSubBytes' | 'InvMixColumns'

/** One field multiply by 2. `shifted` is the 9-bit value before the 11b XOR. */
export interface AesDoubling {
  readonly from: number
  readonly shifted: number
  readonly reduced: boolean
  readonly to: number
}

/** One factor-times-input term of a mixed byte. */
export interface AesTerm {
  /** 2, 3 or 1 to encrypt; 14, 11, 13 or 9 to decrypt. */
  readonly factor: number
  readonly input: number
  /** As many doublings as the factor needs. The inverse factors need 3. */
  readonly doublings: readonly AesDoubling[]
  /** The input and doubled values the factor's set bits pick, low bit first. */
  readonly picks: Bytes
  /** The running XOR of the picks. Its last value is `result`. */
  readonly sums: Bytes
  /** Any doubling needed the 11b XOR. */
  readonly reduced: boolean
  readonly result: number
}

/** One output byte of a mix step: its 4 terms, and the XOR after each term. */
export interface AesColumnByte {
  readonly terms: readonly AesTerm[]
  readonly running: Bytes
  readonly result: number
}

/** One FIPS 197 operation on the state. */
export interface AesStep {
  readonly kind: AesStepKind
  /** Encrypt: 0 to Nr. Decrypt: Nr down to 0. The number of the round key the step's round uses. */
  readonly round: number
  readonly before: Bytes
  readonly after: Bytes
  /** AddRoundKey only. Else null. */
  readonly roundKey: Bytes | null
  /** MixColumns and InvMixColumns only, one entry per state byte in r + 4c order. Else null. */
  readonly terms: readonly AesColumnByte[] | null
}

export interface AesBlockWalk {
  readonly rounds: number
  readonly input: Bytes
  readonly output: Bytes
  readonly steps: readonly AesStep[]
}

/** One word of the key schedule: one row of the FIPS 197 Appendix A tables. A stage the word does not use is null. */
export interface AesKeyWordStep {
  readonly index: number
  /** Nk. The word test of FIPS 197 section 5.2 is index / Nk. */
  readonly divisor: number
  readonly quotient: number
  readonly remainder: number
  /** w[i-1], the table's "temp". */
  readonly previous: Bytes | null
  readonly rotated: Bytes | null
  readonly substituted: Bytes | null
  /** Rcon[i/Nk] as a word: the constant, then 3 zero bytes. */
  readonly rcon: Bytes | null
  readonly afterRcon: Bytes | null
  /** w[i-Nk]. */
  readonly keyBack: Bytes | null
  readonly word: Bytes
}

const diverged = (): AesError => new AesError('AES_WALK_DIVERGED', 'the walk differs from the real AES path')

function requireSame(real: Bytes, walked: Bytes): void {
  if (real.some((b, i) => b !== walked[i])) throw diverged()
}

/** Each value is the one before it, doubled in the field. */
export function roundConstants(count: number): Bytes {
  const values: number[] = []
  for (let i = 0, v = 1; i < count; i++, v = xtime(v)) values.push(v)
  return frozen(values)
}

function doubling(from: number): AesDoubling {
  return Object.freeze({ from, shifted: from << 1, reduced: (from & 0x80) !== 0, to: xtime(from) })
}

/** count - 1 doublings, one between each pair of round constants. */
export function roundConstantSteps(count: number): readonly AesDoubling[] {
  return Object.freeze(roundConstants(count).slice(0, -1).map(doubling))
}

/** Walks the factor's bits from the low end. A set bit picks the value so far; each further bit needs one more doubling. */
function term(factor: number, input: number): AesTerm {
  const doublings: AesDoubling[] = []
  const picks: number[] = [], sums: number[] = []
  let value = input, sum = 0
  for (let bits = factor; bits !== 0; bits >>= 1) {
    if (bits & 1) {
      picks.push(value)
      sum ^= value
      sums.push(sum)
    }
    if (bits >> 1 === 0) break
    const d = doubling(value)
    doublings.push(d)
    value = d.to
  }
  return Object.freeze({
    factor, input, doublings: Object.freeze(doublings), picks: frozen(picks), sums: frozen(sums),
    reduced: doublings.some(d => d.reduced), result: sum,
  })
}

/** One entry per state byte, in r + 4c order. Row r of the matrix multiplies column c of the state. */
export function mixTerms(before: ArrayLike<number>, inverse: boolean): readonly AesColumnByte[] {
  const state = readBlock(before)
  const row = inverse ? INVERSE_MIX_ROW : MIX_ROW
  return Object.freeze(state.map((_, i) => {
    const c = i - (i % 4), r = i % 4
    const terms = [0, 1, 2, 3].map(j => term(row[(j - r + 4) % 4], state[c + j]))
    const running = terms.reduce<number[]>((acc, t) => [...acc, (acc.at(-1) ?? 0) ^ t.result], [])
    return Object.freeze({ terms: Object.freeze(terms), running: frozen(running), result: running[3] })
  }))
}

const step = (kind: AesStepKind, round: number, before: Bytes, after: Bytes, roundKey: Bytes | null = null,
  terms: readonly AesColumnByte[] | null = null): AesStep => Object.freeze({ kind, round, before, after, roundKey, terms })

/** The steps of one walk, built by appending. Each helper takes the current state and returns the state after its step. */
class StepLog {
  readonly steps: AesStep[] = []
  private readonly schedule: KeySchedule

  constructor(schedule: KeySchedule) {
    this.schedule = schedule
  }

  addRoundKey(state: Bytes, round: number): Bytes {
    const key = roundKeyOf(this.schedule, round)
    return this.push(step('AddRoundKey', round, state, xorBytes(state, key), key))
  }

  substitute(state: Bytes, round: number, inverse: boolean): Bytes {
    return this.push(step(inverse ? 'InvSubBytes' : 'SubBytes', round, state, substitute(state, inverse ? INVERSE_SBOX : SBOX)))
  }

  shift(state: Bytes, round: number, inverse: boolean): Bytes {
    return this.push(step(inverse ? 'InvShiftRows' : 'ShiftRows', round, state, move(state, inverse ? INVERSE_SHIFT_ROWS_MAP : SHIFT_ROWS_MAP)))
  }

  /** The real mix makes the state. The terms explain it, and each must give the same byte. */
  mix(state: Bytes, round: number, inverse: boolean): Bytes {
    const terms = mixTerms(state, inverse)
    const after = inverse ? inverseMixColumns(state) : mixColumns(state)
    requireSame(after, frozen(terms.map(t => t.result)))
    return this.push(step(inverse ? 'InvMixColumns' : 'MixColumns', round, state, after, null, terms))
  }

  private push(s: AesStep): Bytes {
    this.steps.push(s)
    return s.after
  }
}

function finish(schedule: KeySchedule, input: Bytes, output: Bytes, real: Bytes, log: StepLog): AesBlockWalk {
  requireSame(real, output)
  return Object.freeze({ rounds: schedule.rounds, input, output, steps: Object.freeze(log.steps) })
}

/** CIPHER, one step per operation. Throws AES_WALK_DIVERGED if the walk differs from the real path. */
export function walkEncrypt(key: ArrayLike<number>, block: ArrayLike<number>): AesBlockWalk {
  const schedule = expandKey(key)
  const input = frozen(readBlock(block))
  const log = new StepLog(schedule)
  let state = log.addRoundKey(input, 0)
  for (let round = 1; round <= schedule.rounds; round++) {
    state = log.substitute(state, round, false)
    state = log.shift(state, round, false)
    if (round < schedule.rounds) state = log.mix(state, round, false)
    state = log.addRoundKey(state, round)
  }
  return finish(schedule, input, state, encryptWith(schedule, input), log)
}

/** INVCIPHER (FIPS 197 section 5.3), one step per operation. Throws AES_WALK_DIVERGED if the walk differs from the real path. */
export function walkDecrypt(key: ArrayLike<number>, block: ArrayLike<number>): AesBlockWalk {
  const schedule = expandKey(key)
  const input = frozen(readBlock(block))
  const log = new StepLog(schedule)
  let state = log.addRoundKey(input, schedule.rounds)
  for (let round = schedule.rounds - 1; round >= 0; round--) {
    state = log.shift(state, round, true)
    state = log.substitute(state, round, true)
    state = log.addRoundKey(state, round)
    if (round > 0) state = log.mix(state, round, true)
  }
  return finish(schedule, input, state, decryptWith(schedule, input), log)
}

/** 4 * (Nr + 1) rows, one per word. Each row's stages are run here, and its word must equal the expanded key's. */
export function walkKeyExpansion(key: ArrayLike<number>): readonly AesKeyWordStep[] {
  const schedule = expandKey(key)
  const nk = schedule.keyWords
  const rcons = roundConstants(10)
  const rows = Array.from({ length: 4 * (schedule.rounds + 1) }, (_, i) => keyWordStep(schedule, i, nk, rcons[Math.floor(i / nk) - 1]))
  return Object.freeze(rows)
}

function keyWordStep(schedule: KeySchedule, i: number, nk: number, rcon: number | undefined): AesKeyWordStep {
  const base = { index: i, divisor: nk, quotient: Math.floor(i / nk), remainder: i % nk }
  const none = { previous: null, rotated: null, substituted: null, rcon: null, afterRcon: null, keyBack: null }
  if (i < nk) return Object.freeze({ ...base, ...none, word: wordOf(schedule, i) })
  const previous = wordOf(schedule, i - 1)
  const keyBack = wordOf(schedule, i - nk)
  const stages: Partial<RotatingStages> = i % nk === 0 ? rotatingStages(previous, rcon!) : nk > 6 && i % nk === 4 ? { substituted: subWord(previous) } : {}
  const last = stages.afterRcon ?? stages.substituted ?? previous
  const word = xorBytes(keyBack, last)
  requireSame(wordOf(schedule, i), word)
  return Object.freeze({ ...base, ...none, ...stages, previous, keyBack, word })
}

interface RotatingStages { rotated: Bytes; substituted: Bytes; rcon: Bytes; afterRcon: Bytes }

function rotatingStages(previous: Bytes, rcon: number): RotatingStages {
  const rotated = rotWord(previous)
  const substituted = subWord(rotated)
  const rconWord = frozen([rcon, 0, 0, 0])
  return { rotated, substituted, rcon: rconWord, afterRcon: xorBytes(substituted, rconWord) }
}
