// What each side holds at a picked event, for the "What each side knows" panel. Pure, so a spec can call it.
import type { TraceEvent } from './types'

// With Show keys OFF a row holds no hex. It shows its fingerprint and its length, and two rows are the same key when their fingerprints match.
export interface HeldRow { holder: string; name: string; hex: string; fingerprint: string; length: number; hidden: string; derivedFrom: string[]; fresh: boolean }

const isWire = (e: TraceEvent) => e.type === 'wire.sent' || e.type === 'wire.received'

/**
 * The seqs of setup events: an event that comes before its side's first wire event. The engine runs client and server on 2 threads, so
 * the order of events across the 2 sides changes from run to run, and a slow side can load its key after the other side has sent.
 * Within one side the order is stable. A key a side learns before its first wire event depends on no message, so it counts as held
 * from the start of the run (the lead on #297's bytes-grid red). A logical clock from the Host replaces this rule later (#304).
 * A side with no wire event in the run gets no setup events. Lesson 7's attacker opens a recording after both runs end and never
 * touches the wire, so its secrets show only from their own events (Jared on #305).
 */
function setupSeqs(events: readonly TraceEvent[]): Set<number> {
  const firstWire = new Map<string, number>()
  for (const e of events) if (isWire(e) && !firstWire.has(e.actor)) firstWire.set(e.actor, e.seq)
  const out = new Set<number>()
  for (const e of events) {
    const first = firstWire.get(e.actor)
    if (first !== undefined && e.seq < first) out.add(e.seq)
  }
  return out
}

/**
 * The rows each holder holds at the picked event (seq upTo). A row exists when the holder gained the value at or before that event, or
 * gained it in a setup event of its own side, before that side sent or received any message.
 */
export function heldAt(events: readonly TraceEvent[], upTo: number): HeldRow[] {
  const setup = setupSeqs(events)
  const m = new Map<string, HeldRow>()
  for (const e of events) {
    if (e.seq > upTo && !setup.has(e.seq)) continue
    for (const s of e.secrets) m.set(`${s.holder.toLowerCase()}.${s.name}`, { holder: s.holder.toLowerCase(), name: s.name, hex: s.hex, fingerprint: s.fingerprint, length: s.length, hidden: s.hidden, derivedFrom: s.derivedFrom, fresh: e.seq === upTo })
  }
  return [...m.values()]
}
