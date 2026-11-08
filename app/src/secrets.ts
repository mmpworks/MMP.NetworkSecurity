// What each side holds at a picked event, for the "What each side knows" panel. Pure, so a spec can call it.
import type { TraceEvent } from './types'

// With Show keys OFF a row holds no hex. It shows its fingerprint and its length, and two rows are the same key when their fingerprints match.
export interface HeldRow { holder: string; name: string; hex: string; fingerprint: string; length: number; hidden: string; derivedFrom: string[]; fresh: boolean }

/** The rows each holder holds at the picked event (seq upTo). A row exists only when the holder gained the value at or before that event. */
export function heldAt(events: readonly TraceEvent[], upTo: number): HeldRow[] {
  const m = new Map<string, HeldRow>()
  for (const e of events) {
    if (e.seq > upTo) break
    for (const s of e.secrets) m.set(`${s.holder.toLowerCase()}.${s.name}`, { holder: s.holder.toLowerCase(), name: s.name, hex: s.hex, fingerprint: s.fingerprint, length: s.length, hidden: s.hidden, derivedFrom: s.derivedFrom, fresh: e.seq === upTo })
  }
  return [...m.values()]
}
