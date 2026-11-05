import { hexToBytes } from './layout'
import type { TraceEvent } from './types'

// Pure helpers for the lesson views (pictures, measures). A test can call every function here.

/** `name=value;name=value` from a measure.result event. */
export function parseDetail(detail: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const part of detail.split(';')) {
    const at = part.indexOf('=')
    if (at > 0) out[part.slice(0, at).trim()] = part.slice(at + 1).trim()
  }
  return out
}

export const PICTURE_BYTES = 64 * 64

export interface Picture { clear: number[]; locked: number[]; mode: string }

/** A picture message is a wire.sent whose plain bytes are 64 by 64. The locked picture is the first 4,096 bytes of its `cipher` field. */
export function pictureOf(e: TraceEvent | null): Picture | null {
  if (!e || e.type !== 'wire.sent' || e.plain.length !== PICTURE_BYTES * 2) return null
  const cipher = e.fields.find(f => f.name === 'cipher')
  if (!cipher) return null
  const wire = hexToBytes(e.wire)
  return { clear: hexToBytes(e.plain), locked: wire.slice(cipher.offset, cipher.offset + PICTURE_BYTES), mode: e.message }
}

export interface Avalanche { flipped: boolean[]; count: number }

/** Two 32-byte digests in `plain`. A cell is true where the same bit differs between them. */
export function avalancheOf(plainHex: string): Avalanche | null {
  const b = hexToBytes(plainHex)
  if (b.length !== 64) return null
  const flipped: boolean[] = []
  for (let i = 0; i < 32; i++) for (let bit = 7; bit >= 0; bit--) flipped.push(((b[i] ^ b[32 + i]) >> bit & 1) === 1)
  return { flipped, count: flipped.filter(Boolean).length }
}

export function percent(part: number, whole: number): number {
  return whole > 0 ? Math.round((part / whole) * 100) : 0
}
