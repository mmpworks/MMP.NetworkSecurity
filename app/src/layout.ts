import type { TraceCheck, TraceEvent, TraceField } from './types'

// Pure layout and byte helpers. The diagram and the inspector call these, and a test can too.

export const ROW_H = 56
export const LANE_GAP = 220
export const HEAD_H = 54
export const LEFT = 110
// In a pane too narrow for the natural spacing, the lanes move closer, down to these floors: a lane head is 140 wide, and a note 180.
export const MIN_LANE_GAP = 160
export const MIN_LEFT = 90

/** The lane spacing for a pane `avail` wide: the natural spacing when it fits, else closer, never below the floors. Pure, so a test can call it. */
export function laneSpacing(lanes: number, avail?: number): { left: number; gap: number } {
  const natural = LEFT * 2 + Math.max(0, lanes - 1) * LANE_GAP
  if (!avail || lanes < 2 || natural <= avail) return { left: LEFT, gap: LANE_GAP }
  return { left: MIN_LEFT, gap: Math.max(MIN_LANE_GAP, Math.min(LANE_GAP, (avail - MIN_LEFT * 2) / (lanes - 1))) }
}

export interface Lane { name: string; x: number }
export interface Row {
  seq: number
  y: number
  kind: 'arrow' | 'check' | 'note' | 'divider'
  fromX: number
  toX: number
  label: string
  bytes: number
  protectedBytes: boolean
  unreadable: boolean
  check: TraceCheck | null
  head: string
  /** `hop1` or `hop2` on the bridge lesson, empty elsewhere. */
  hop?: string
}
export interface Layout { lanes: Lane[]; rows: Row[]; width: number; height: number; learned: number; total: number }

// Only wire.sent draws an arrow. wire.received repeats the same bytes for the interop check, and engine events carry no wire.
export const isWireSent = (e: TraceEvent): boolean => e.type === 'wire.sent'
// Protected means the engine marked part of the wire bytes as hidden from the wire (visibleToWire false). A tampered byte also makes
// plain differ from wire, so comparing the two would call a tamper "encrypted".
export const isProtected = (e: TraceEvent): boolean => e.wire.length > 0 && e.fields.some(f => !f.visibleToWire)
// Events that draw a marker on one lane: key installs, certificates issued, keys erased, alerts.
// The bridge lesson (9) has actors that own no lane: the PIN pad sits on the CE device and the bank behind the server (docs/lesson-9-names.md section 1).
const LANE_ALIAS: Record<string, string> = { reader: 'ce', bank: 'server' }

export const isNoteEvent = (e: TraceEvent): boolean =>
  e.type.startsWith('keys.') || ['pin.block.locked', 'ce.envelope.taken', 'gateway.envelope.relayed', 'ce.reply.relayed'].includes(e.type) || e.type.startsWith('ssh.weak.') || ['ca.certificate.issued', 'dukpt.key.erased', 'tls.alert.sent', 'ssh.hostkey.seen', 'ssh.exec.exit'].includes(e.type)

/** The protocol of an event: the third part of its stream id (`<session>/client/tls11` and `<session>/client/tls11/wire` both give `tls11`). */
export const protocolOf = (e: TraceEvent): string => e.streamId.split('/')[2] ?? ''
export const byteCount = (hex: string): number => hex.length >> 1

export function laneNames(events: readonly TraceEvent[], declared: readonly string[]): string[] {
  const out = declared.map(l => l.toLowerCase())
  for (const e of events) for (const n of [e.from, e.to]) { const k = n.toLowerCase(); if (k && !out.includes(k)) out.push(k) }
  if (out.length === 0) for (const e of events) { const k = e.actor.toLowerCase(); if (k && !out.includes(k)) out.push(k) }
  return out
}

/** `avail` is the pane's width. With it, a narrow pane draws its lanes closer (laneSpacing), so the drawing scrolls sideways less or not at all. */
export function layoutDiagram(events: readonly TraceEvent[], declared: readonly string[], view: 'endpoints' | 'eavesdropper', avail?: number): Layout {
  const names = laneNames(events, declared)
  const { left, gap } = laneSpacing(names.length, avail)
  const lanes: Lane[] = names.map((name, i) => ({ name, x: left + i * gap }))
  const xOf = (n: string): number => { const k = n.toLowerCase(); return lanes.find(l => l.name === (LANE_ALIAS[k] && !lanes.some(x => x.name === k) ? LANE_ALIAS[k] : k))?.x ?? left }
  const rows: Row[] = []
  let learned = 0
  let total = 0
  let lastProto = ''
  for (const e of events) {
    const prot = isProtected(e)
    const isArrow = isWireSent(e) && !!e.from && !!e.to && e.from.toLowerCase() !== e.to.toLowerCase()
    // A run with two rounds on two streams (lesson 8: modern, then legacy) gets a divider where the stream changes.
    if (isArrow && lastProto && protocolOf(e) !== lastProto) {
      rows.push({ seq: -rows.length - 1, y: HEAD_H + 30 + rows.length * ROW_H, kind: 'divider', fromX: left, toX: left, label: `next round: ${protocolOf(e)}`, bytes: 0, protectedBytes: false, unreadable: false, check: null, head: '' })
    }
    if (isArrow) lastProto = protocolOf(e)
    const y = HEAD_H + 30 + rows.length * ROW_H
    if (isArrow) {
      total++
      if (!prot) learned++
      const hidden = view === 'eavesdropper' && prot
      rows.push({
        seq: e.seq, y, kind: 'arrow', fromX: xOf(e.from), toX: xOf(e.to),
        label: hidden ? 'unreadable' : e.message || e.type, bytes: byteCount(e.wire), protectedBytes: prot, unreadable: hidden, check: view === 'eavesdropper' ? null : e.check, head: e.wire.slice(0, 16), hop: e.hop,
      })
    } else if (e.check && view !== 'eavesdropper') {
      rows.push({ seq: e.seq, y, kind: 'check', fromX: xOf(e.actor), toX: xOf(e.actor), label: e.check.name, bytes: 0, protectedBytes: false, unreadable: false, check: e.check, head: '' })
    } else if (isNoteEvent(e) && view !== 'eavesdropper') {
      rows.push({ seq: e.seq, y, kind: 'note', fromX: xOf(e.actor), toX: xOf(e.actor), label: e.detail || e.message || e.type, bytes: 0, protectedBytes: true, unreadable: false, check: null, head: '' })
    }
  }
  return { lanes, rows, width: left * 2 + Math.max(0, lanes.length - 1) * gap, height: HEAD_H + 60 + rows.length * ROW_H, learned, total }
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
