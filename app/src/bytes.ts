import { isProtected } from './layout'
import type { TraceEvent, TraceField } from './types'

// What the Message bytes panel draws for one event. Pure, so a spec can pin it (e2e/bytes-layout.spec.ts).
//
// An event can carry two buffers: `plain` (the readable bytes before protection) and `wire` (the bytes that travel).
// The engine lists its fields against one of them, and the panel must draw each field on that buffer. Lesson 1 lists
// type, length, nonce, cipher and tag against the 96 wire bytes while `plain` holds the 64 readable bytes, so drawing
// the fields on `plain` put the nonce over the letters "Pump".

export interface Span { offset: number; length: number }
export interface BytesView {
  /** The readable bytes before protection. Null when they equal the wire, or when the eavesdropper cannot read them. */
  before: { hex: string } | null
  /** The bytes on the wire. Null for an engine event that moves no bytes. */
  after: { hex: string } | null
  /** True when the eavesdropper view hides readable bytes that the endpoints can see. */
  beforeHidden: boolean
  /** True in the eavesdropper view for an event with readable bytes that never crossed the wire: a listener sees nothing of it. */
  neverOnWire: boolean
  /** The buffer the fields describe. */
  fieldsOn: 'before' | 'after'
  /** The fields that fit their buffer. */
  fields: TraceField[]
  /** Where the readable bytes went on the wire: the same bytes in the clear, or the span they were locked into. */
  source: Span | null
}

const lengthOf = (hex: string): number => hex.length >> 1
const endOf = (fields: readonly TraceField[]): number => fields.reduce((n, f) => Math.max(n, f.offset + f.length), 0)
const fits = (fields: readonly TraceField[], len: number): TraceField[] => fields.filter(f => f.offset + f.length <= len)

/** Byte offset of `plain` inside `wire`, or -1. Only whole-byte positions count. */
function byteIndexOf(wire: string, plain: string): number {
  for (let i = wire.indexOf(plain); i >= 0; i = wire.indexOf(plain, i + 1)) if (i % 2 === 0) return i / 2
  return -1
}

/** The wire span the readable bytes became: the payload in the clear, else the first field hidden from the wire. */
function sourceOf(e: TraceEvent, fields: readonly TraceField[]): Span | null {
  const at = byteIndexOf(e.wire, e.plain)
  if (at >= 0) return { offset: at, length: lengthOf(e.plain) }
  const locked = fields.find(f => !f.visibleToWire && f.kind === 'cipher') ?? fields.find(f => !f.visibleToWire)
  return locked ? { offset: locked.offset, length: locked.length } : null
}

export function bytesView(e: TraceEvent, view: 'endpoints' | 'eavesdropper' | 'both'): BytesView {
  const wireLen = lengthOf(e.wire)
  const plainLen = lengthOf(e.plain)
  const end = endOf(e.fields)

  // An engine event: only the readable bytes. Its fields often describe the wire it will become, so they show only when they fill it.
  if (!wireLen) {
    if (view === 'eavesdropper') return { before: null, after: null, beforeHidden: false, neverOnWire: plainLen > 0, fieldsOn: 'before', fields: [], source: null }
    return { before: plainLen ? { hex: e.plain } : null, after: null, beforeHidden: false, neverOnWire: false, fieldsOn: 'before', fields: end === plainLen ? [...e.fields] : [], source: null }
  }

  // In the clear and unchanged: one grid is enough.
  if (!plainLen || e.plain === e.wire) return { before: null, after: { hex: e.wire }, beforeHidden: false, neverOnWire: false, fieldsOn: 'after', fields: fits(e.fields, wireLen), source: null }

  // Fields that end where the readable bytes end, and not where the wire ends, describe the inner message (TLS 1.3 records).
  const fieldsOn = end === plainLen && end !== wireLen ? 'before' : 'after'
  const hide = view === 'eavesdropper' && isProtected(e)
  const fields = fits(e.fields, fieldsOn === 'before' ? plainLen : wireLen)
  return {
    before: hide ? null : { hex: e.plain },
    after: { hex: e.wire },
    beforeHidden: hide,
    neverOnWire: false,
    fieldsOn,
    fields: hide && fieldsOn === 'before' ? [] : fields,
    source: fieldsOn === 'after' ? sourceOf(e, fields) : null,
  }
}
