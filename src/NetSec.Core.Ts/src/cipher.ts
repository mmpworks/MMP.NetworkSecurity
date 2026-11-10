// The real AES path, FIPS 197 sections 5.1 to 5.3. It mirrors AesKey.cs: SubBytes and ShiftRows run in one pass.
// The walk (walk.ts) runs the steps one at a time and checks its result against this path.
// The state is 16 bytes, column by column, so row r of column c is state[r + 4c].
// Every function returns a new array and leaves its arguments as they were.
import { BLOCK_SIZE, frozen, readBlock, readKey, type Bytes } from './bytes.ts'
import { INVERSE_SBOX, SBOX, TIMES, xtime } from './field.ts'

/** state[i] takes the byte from state[map[i]]. */
export const SHIFT_ROWS_MAP: readonly number[] = Object.freeze([0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11])
export const INVERSE_SHIFT_ROWS_MAP: readonly number[] = Object.freeze([0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3])

/** The expanded key. `bytes` holds the 4 * (rounds + 1) words, 4 bytes each, word after word. */
export interface KeySchedule {
  /** Nk: 4, 6 or 8. */
  readonly keyWords: number
  /** Nr: 10, 12 or 14. */
  readonly rounds: number
  readonly bytes: Bytes
}

export const rotWord = (t: Bytes): Bytes => frozen([t[1], t[2], t[3], t[0]])
export const subWord = (t: Bytes): Bytes => frozen(t.map(b => SBOX[b]))
export const xorBytes = (a: Bytes, b: Bytes): Bytes => frozen(a.map((x, i) => x ^ b[i]))

/** KeyExpansion, FIPS 197 section 5.2. Each word is the word before it, changed at key-length steps, XOR the word one key back. */
export function expandKey(key: ArrayLike<number>): KeySchedule {
  const k = readKey(key)
  const keyWords = k.length / 4
  const rounds = keyWords + 6
  const words: Bytes[] = Array.from({ length: keyWords }, (_, i) => frozen(k.slice(4 * i, 4 * i + 4)))
  let rcon = 1
  for (let i = keyWords; i < 4 * (rounds + 1); i++) {
    let temp = words[i - 1]
    if (i % keyWords === 0) {
      const sub = subWord(rotWord(temp))
      temp = frozen([sub[0] ^ rcon, sub[1], sub[2], sub[3]])
      rcon = xtime(rcon)
    } else if (keyWords > 6 && i % keyWords === 4) {
      temp = subWord(temp)
    }
    words.push(xorBytes(words[i - keyWords], temp))
  }
  return Object.freeze({ keyWords, rounds, bytes: frozen(words.flat()) })
}

export function wordOf(schedule: KeySchedule, i: number): Bytes {
  return frozen(schedule.bytes.slice(4 * i, 4 * i + 4))
}

export function roundKeyOf(schedule: KeySchedule, round: number): Bytes {
  return frozen(schedule.bytes.slice(round * BLOCK_SIZE, (round + 1) * BLOCK_SIZE))
}

export const substitute = (state: Bytes, box: Bytes): Bytes => frozen(state.map(b => box[b]))
export const move = (state: Bytes, map: readonly number[]): Bytes => frozen(map.map(from => state[from]))

/** SubBytes and ShiftRows, or their inverses, in one pass. The order of the two makes no difference to the result. */
const substituteAndMove = (state: Bytes, box: Bytes, map: readonly number[]): Bytes => frozen(map.map(from => box[state[from]]))

/** One column's 4 bytes, mixed by the circulant matrix whose first row is `row` (FIPS 197 sections 5.1.3 and 5.3.3). */
function mixWith(state: Bytes, row: readonly number[]): Bytes {
  const times = (f: number, b: number): number => (f === 1 ? b : TIMES[f][b])
  return frozen(state.map((_, i) => {
    const c = i - (i % 4), r = i % 4
    return [0, 1, 2, 3].reduce((sum, j) => sum ^ times(row[(j - r + 4) % 4], state[c + j]), 0)
  }))
}

export const MIX_ROW: readonly number[] = Object.freeze([2, 3, 1, 1])
export const INVERSE_MIX_ROW: readonly number[] = Object.freeze([14, 11, 13, 9])
export const mixColumns = (state: Bytes): Bytes => mixWith(state, MIX_ROW)
export const inverseMixColumns = (state: Bytes): Bytes => mixWith(state, INVERSE_MIX_ROW)

/** CIPHER, FIPS 197 Algorithm 1. */
export function encryptWith(schedule: KeySchedule, block: Bytes): Bytes {
  const nr = schedule.rounds
  let state = xorBytes(block, roundKeyOf(schedule, 0))
  for (let round = 1; round < nr; round++) {
    state = xorBytes(mixColumns(substituteAndMove(state, SBOX, SHIFT_ROWS_MAP)), roundKeyOf(schedule, round))
  }
  return xorBytes(substituteAndMove(state, SBOX, SHIFT_ROWS_MAP), roundKeyOf(schedule, nr))
}

/** INVCIPHER, FIPS 197 Algorithm 3 (section 5.3): the plain round keys, AddRoundKey before InvMixColumns. */
export function decryptWith(schedule: KeySchedule, block: Bytes): Bytes {
  const nr = schedule.rounds
  let state = xorBytes(block, roundKeyOf(schedule, nr))
  for (let round = nr - 1; round > 0; round--) {
    state = inverseMixColumns(xorBytes(substituteAndMove(state, INVERSE_SBOX, INVERSE_SHIFT_ROWS_MAP), roundKeyOf(schedule, round)))
  }
  return xorBytes(substituteAndMove(state, INVERSE_SBOX, INVERSE_SHIFT_ROWS_MAP), roundKeyOf(schedule, 0))
}

/** One block, encrypted. The key is 16, 24 or 32 bytes; the block is 16. */
export function encryptBlock(key: ArrayLike<number>, block: ArrayLike<number>): Bytes {
  return encryptWith(expandKey(key), frozen(readBlock(block)))
}

/** One block, decrypted with the inverse cipher of FIPS 197 section 5.3. */
export function decryptBlock(key: ArrayLike<number>, block: ArrayLike<number>): Bytes {
  return decryptWith(expandKey(key), frozen(readBlock(block)))
}
