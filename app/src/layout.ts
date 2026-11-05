import type { TraceCheck, TraceEvent, TraceField } from './types'

// Pure layout and byte helpers. The diagram and the inspector call these, and a test can too.

export const ROW_H = 56
export const LANE_GAP = 220
export const HEAD_H = 54
export const LEFT = 110

export interface Lane { name: string; x: number }
export interface Row {
  seq: number
  y: number
  kind: 'arrow' | 'check' | 'note'
  fromX: number
  toX: number
  label: string
  bytes: number
  protectedBytes: boolean
  unreadable: boolean
  check: TraceCheck | null
  head: string
}
export interface Layout { lanes: Lane[]; rows: Row[]; width: number; height: number; learned: number; total: number }

export const isProtected = (e: TraceEvent): boolean => e.plain.length > 0 && e.plain !== e.wire
export const byteCount = (hex: string): number => hex.length >> 1

export function laneNames(events: readonly TraceEvent[], declared: readonly string[]): string[] {
  const out = declared.map(l => l.toLowerCase())
  for (const e of events) for (const n of [e.from, e.to]) { const k = n.toLowerCase(); if (k && !out.includes(k)) out.push(k) }
  if (out.length === 0) for (const e of events) { const k = e.actor.toLowerCase(); if (k && !out.includes(k)) out.push(k) }
  return out
}

export function layoutDiagram(events: readonly TraceEvent[], declared: readonly string[], view: 'endpoints' | 'eavesdropper'): Layout {
  const names = laneNames(events, declared)
  const lanes: Lane[] = names.map((name, i) => ({ name, x: LEFT + i * LANE_GAP }))
  const xOf = (n: string): number => lanes.find(l => l.name === n.toLowerCase())?.x ?? LEFT
  const rows: Row[] = []
  let learned = 0
  let total = 0
  for (const e of events) {
    const y = HEAD_H + 30 + rows.length * ROW_H
    const prot = isProtected(e)
    if (e.from && e.to && e.from.toLowerCase() !== e.to.toLowerCase()) {
      total++
      if (!prot) learned++
      const hidden = view === 'eavesdropper' && prot
      rows.push({
        seq: e.seq, y, kind: 'arrow', fromX: xOf(e.from), toX: xOf(e.to),
        label: hidden ? 'unreadable' : e.message || e.type, bytes: byteCount(e.wire), protectedBytes: prot, unreadable: hidden, check: view === 'eavesdropper' ? null : e.check, head: e.wire.slice(0, 16),
      })
    } else if (e.check && view !== 'eavesdropper') {
      rows.push({ seq: e.seq, y, kind: 'check', fromX: xOf(e.actor), toX: xOf(e.actor), label: e.check.name, bytes: 0, protectedBytes: false, unreadable: false, check: e.check, head: '' })
    } else if (e.type.startsWith('keys.') && view !== 'eavesdropper') {
      rows.push({ seq: e.seq, y, kind: 'note', fromX: xOf(e.actor), toX: xOf(e.actor), label: e.message || e.type, bytes: 0, protectedBytes: true, unreadable: false, check: null, head: '' })
    }
  }
  return { lanes, rows, width: LEFT * 2 + Math.max(0, lanes.length - 1) * LANE_GAP, height: HEAD_H + 60 + rows.length * ROW_H, learned, total }
}

export function hexToBytes(hex: string): number[] {
  const out: number[] = []
  for (let i = 0; i + 1 < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16))
  return out
}

export const h2 = (n: number): string => n.toString(16).padStart(2, '0')

/** Field that owns a byte offset, or null. The first field listed wins when spans overlap. */
export function fieldAt(fields: readonly TraceField[], offset: number): TraceField | null {
  for (const f of fields) if (offset >= f.offset && offset < f.offset + f.length) return f
  return null
}

export const ASCII = (b: number): string => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')
