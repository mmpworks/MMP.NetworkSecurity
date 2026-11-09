// The AES walk's pure functions (docs/walkthrough-design.md sections 2.2, 2.2a, 3.7). No Vue and no store, so a spec can call each one.
// Every state and every byte comes from the engine's block reply. Nothing here computes AES.

/** One product in a MixColumns byte: factor times input, as the engine worked it (design section 2.2c). */
export interface AesTerm {
  factor: number; input: string; reduced: boolean; result: string
  /** One entry per field doubling: the byte in, the shift as 3 hex digits before the 11b XOR, whether it reduced, and the byte out. */
  doublings?: AesDoubling[]
  /** For a factor with more than one part (3, and the inverse factors): the parts picked, and the running sums, low bit first. */
  picks?: string[]
  sums?: string[]
}
export interface AesDoubling { from: string; shifted: string; reduced: boolean; to: string }
/** One output byte of a MixColumns step: its 4 products, and their XOR. */
export interface AesMixedByte { result: string; parts: AesTerm[] }
export interface AesStepRow { kind: string; round: number; state: string; roundKey?: string; terms?: AesMixedByte[] | null }
export interface AesRun { input: string; output: string; steps: AesStepRow[] }
/** One word of the key schedule (design section 2.2b). A key word holds only `word`; a stage the engine did not run is null. */
export interface AesKeyWordRow {
  i: number
  divisor?: number
  quotient?: number
  remainder?: number
  previous: string | null
  rotated: string | null
  substituted: string | null
  rcon: string | null
  afterRcon: string | null
  keyBack: string | null
  word: string
}
/** How the engine cut the typed text into chapter 1's block (design 2.2g). Byte counts, as UTF-8. */
export interface AesTypedCut { block: string; usedBytes: number; paddingBytes: number; notIncludedBytes: number; splitCharacterBytesIn: number }

/** One row of the long-text reply: one 16-byte block of the text, as hex. */
export interface AesLongRow { block: number; data: string }

/**
 * Splits typed text at a byte count, as UTF-8, for the box's marking: the characters the block uses, a character that crosses
 * the edge, and the rest. It counts bytes and computes no crypto value. `used` comes from the engine's cut.
 */
export function splitAtBytes(text: string, used: number): { inside: string; split: string; outside: string } {
  const enc = new TextEncoder()
  let bytes = 0, i = 0
  const chars = [...text]
  while (i < chars.length && bytes + enc.encode(chars[i]).length <= used) bytes += enc.encode(chars[i++]).length
  const split = i < chars.length && bytes < used ? chars[i++] : ''
  return { inside: chars.slice(0, i - (split ? 1 : 0)).join(''), split, outside: chars.slice(i).join('') }
}

/** The public tables route: the S-boxes, the round constants, and the size table. It holds no key byte. */
export interface AesSize { keyBits: number; keyWords: number; rounds: number; roundKeys: number; words: number; rconUsed: number }
export interface AesTables { sbox: string; inverseSbox: string; shiftRows: number[]; inverseShiftRows: number[]; rcon: string; sizes: AesSize[] }
export interface AesBlockReply {
  source?: string
  keySource?: string
  keyBits: number
  rounds: number
  inputHex: string
  keyWords: AesKeyWordRow[]
  forward: AesRun
  inverse: AesRun | null
  /** Whether this run sent the block in ECB (design sections 2.2g and 2.4). */
  wire?: { status: 'notSent' | 'match' | 'differs' | string; message: string }
}

/**
 * One stop of the walk, in Next order: the first view fills the block one byte at a time, then the key schedule builds one word at a time,
 * then the encrypt steps, the decrypt Start view, and the decrypt steps. On a key schedule stop the grid still shows the block.
 * `prev` is the state the stop before showed, so a lookup on a SubBytes step can name the byte that went in.
 */
export type Stop =
  | { kind: 'fill'; filled: number; state: string }
  | { kind: 'keys'; built: number; state: string }
  | { kind: 'step'; run: 'encrypt' | 'decrypt'; step: AesStepRow; state: string; prev: string }
  | { kind: 'decrypt-start'; state: string }

/** Nk, the number of key words, from the tables route's size table. */
export function keyWordsOf(tables: AesTables, keyBits: number): number {
  const size = tables.sizes.find(s => s.keyBits === keyBits)
  if (!size) throw new Error(`the size table has no ${keyBits}-bit row`)
  return size.keyWords
}

/** FIPS 197 section 3.4: row r, column c holds byte r + 4c. */
export const cellIndex = (r: number, c: number): number => r + 4 * c

export const byteAt = (hex: string, i: number): string => hex.slice(2 * i, 2 * i + 2).toLowerCase()

/** The character a byte stands for, when it is printable ASCII. Otherwise an empty string. */
export function letterOf(byte: string): string {
  const n = parseInt(byte, 16)
  return n >= 0x20 && n < 0x7f ? String.fromCharCode(n) : ''
}

/** The text a block holds, with a mark for each byte that is not printable: '.' by default, '·' where a '.' could pass for text. */
export function textOf(hex: string, mark = '.'): string {
  let out = ''
  for (let i = 0; i < hex.length / 2; i++) out += letterOf(byteAt(hex, i)) || mark
  return out
}

/** The walk's stops. `nk` is the number of key words: the key schedule starts with them filled, and Next builds each later word. */
export function stopsOf(b: AesBlockReply, nk: number): Stop[] {
  const stops: Stop[] = []
  for (let filled = 0; filled <= 16; filled++) stops.push({ kind: 'fill', filled, state: b.inputHex })
  for (let built = 0; built <= b.keyWords.length - nk; built++) stops.push({ kind: 'keys', built, state: b.inputHex })
  let prev = b.inputHex
  for (const step of b.forward.steps) { stops.push({ kind: 'step', run: 'encrypt', step, state: step.state, prev }); prev = step.state }
  if (b.inverse) {
    stops.push({ kind: 'decrypt-start', state: b.forward.output })
    prev = b.forward.output
    for (const step of b.inverse.steps) { stops.push({ kind: 'step', run: 'decrypt', step, state: step.state, prev }); prev = step.state }
  }
  return stops
}

/**
 * The part of the walk a stop belongs to. Play runs to the end of one part and stops (design 2.8): the first view, one grid of the
 * key schedule, or one round of encrypt or decrypt.
 */
export function playGroupOf(stop: Stop, nk: number): string {
  if (stop.kind === 'fill') return 'fill'
  if (stop.kind === 'keys') return `keys-${Math.floor((nk + stop.built - 1) / 4)}`
  if (stop.kind === 'decrypt-start') return 'decrypt-start'
  return `${stop.run}-${stop.step.round}`
}

/** The expanded key as one hex string, word after word, from the reply's rows. */
export function expandedHex(rows: AesKeyWordRow[]): string {
  return rows.slice().sort((a, b) => a.i - b.i).map(r => r.word.toLowerCase()).join('')
}

/** The sentence that states the word test of FIPS 197 section 5.2 (design section 2.2b). It names only the stages the row holds. */
export function wordTest(row: AesKeyWordRow, nk: number): string {
  const w = `w${row.i}`
  if (row.i < nk || row.divisor == null) return `${w} is part of the key, so nothing is calculated.`
  if (row.rotated) return `${row.i} ÷ ${row.divisor} = ${row.quotient}, no remainder, so ${w} rotates. It is rotation ${row.quotient}, so it takes round constant ${row.quotient}: ${byteAt(row.rcon ?? '', 0)}.`
  if (row.substituted) return `${row.i} ÷ ${row.divisor} leaves ${row.remainder}, so ${w} gets the S-box step only. AES-256 adds this rule.`
  return `${row.i} ÷ ${row.divisor} leaves ${row.remainder}, so ${w} is plain: no rotation.`
}

/** What a cell shows at a stop: its 2 hex digits, or nothing while the first view has not reached it. */
export function cellText(stop: Stop, r: number, c: number): string {
  const i = cellIndex(r, c)
  if (stop.kind === 'fill' && i >= stop.filled) return ''
  return byteAt(stop.state, i)
}
