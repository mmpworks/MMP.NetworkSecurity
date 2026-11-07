// The AES walk's pure functions (docs/walkthrough-design.md sections 2.2, 2.2a, 3.7). No Vue and no store, so a spec can call each one.
// Every state and every byte comes from the engine's block reply. Nothing here computes AES.

export interface AesStepRow { kind: string; round: number; state: string; roundKey?: string; terms?: unknown[] | null }
export interface AesRun { input: string; output: string; steps: AesStepRow[] }
export interface AesKeyWordRow { i: number; previous: string; rotated: string; substituted: string; rcon: string; afterRcon: string; keyBack: string; word: string }
export interface AesBlockReply {
  source?: string
  keySource?: string
  keyBits: number
  rounds: number
  inputHex: string
  keyWords: AesKeyWordRow[]
  forward: AesRun
  inverse: AesRun | null
}

/** One stop of the walk, in Next order: the first view fills the block one byte at a time, then the encrypt steps, the decrypt Start view, and the decrypt steps. */
export type Stop =
  | { kind: 'fill'; filled: number; state: string }
  | { kind: 'step'; run: 'encrypt' | 'decrypt'; step: AesStepRow; state: string }
  | { kind: 'decrypt-start'; state: string }

/** FIPS 197 section 3.4: row r, column c holds byte r + 4c. */
export const cellIndex = (r: number, c: number): number => r + 4 * c

export const byteAt = (hex: string, i: number): string => hex.slice(2 * i, 2 * i + 2).toLowerCase()

/** The character a byte stands for, when it is printable ASCII. Otherwise an empty string. */
export function letterOf(byte: string): string {
  const n = parseInt(byte, 16)
  return n >= 0x20 && n < 0x7f ? String.fromCharCode(n) : ''
}

/** The text a block holds, with a dot for each byte that is not printable. */
export function textOf(hex: string): string {
  let out = ''
  for (let i = 0; i < hex.length / 2; i++) out += letterOf(byteAt(hex, i)) || '.'
  return out
}

export function stopsOf(b: AesBlockReply): Stop[] {
  const stops: Stop[] = []
  for (let filled = 0; filled <= 16; filled++) stops.push({ kind: 'fill', filled, state: b.inputHex })
  for (const step of b.forward.steps) stops.push({ kind: 'step', run: 'encrypt', step, state: step.state })
  if (b.inverse) {
    stops.push({ kind: 'decrypt-start', state: b.forward.output })
    for (const step of b.inverse.steps) stops.push({ kind: 'step', run: 'decrypt', step, state: step.state })
  }
  return stops
}

/** What a cell shows at a stop: its 2 hex digits, or nothing while the first view has not reached it. */
export function cellText(stop: Stop, r: number, c: number): string {
  const i = cellIndex(r, c)
  if (stop.kind === 'fill' && i >= stop.filled) return ''
  return byteAt(stop.state, i)
}
