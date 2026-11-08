// The two-run layout's pairing (docs/sections-plan.md item 3, notes 3 to 5; Steve, Q4 A). Pure, so a spec can call it.
// An attack is a fork: the Host reruns the lesson with the parent's seed and the attack's plan. So the normal run and the attacked
// run pair event by event on (stream, place in stream) until the attack changes the run.
import type { TraceEvent } from './types'

export interface RunPair { key: string; normal: TraceEvent | null; attacked: TraceEvent | null; changed: boolean }

/** The stream key without the session id, which differs between the 2 runs: "<session>/client/aes" pairs as "client/aes". */
export const streamKey = (e: TraceEvent): string => `${e.streamId.split('/').slice(1).join('/')}#${e.streamSeq}`

/** Two events at one key differ when their type, message or wire bytes differ. */
const differs = (a: TraceEvent, b: TraceEvent): boolean => a.type !== b.type || a.message !== b.message || a.wire !== b.wire

/**
 * A wire event: bytes on the socket, on a "<side>/<protocol>/wire" stream. A receive is one event per socket read, so 2 messages can
 * arrive in one read, and the count changes from run to run (docs/learnings.md item 3). So steps come from the engine streams only.
 */
export const isWire = (e: TraceEvent): boolean => e.streamId.endsWith('/wire')

/** A run's events by key. A key held twice is a stream opened twice, which pairing by stream cannot tell apart, so it is reported. */
function byKey(events: readonly TraceEvent[], keep: (e: TraceEvent) => boolean): { map: Map<string, TraceEvent>; duplicates: string[] } {
  const map = new Map<string, TraceEvent>()
  const duplicates: string[] = []
  for (const e of events) {
    if (!e.streamId || !keep(e)) continue
    const key = streamKey(e)
    if (map.has(key)) duplicates.push(key)
    else map.set(key, e)
  }
  return { map, duplicates }
}

/** The stream name and place of a key, for the order of the steps. */
const parts = (key: string): { stream: string; seq: number } => {
  const at = key.lastIndexOf('#')
  return { stream: key.slice(0, at), seq: Number(key.slice(at + 1)) }
}

const byPlace = (x: string, y: string) => {
  const px = parts(x), py = parts(y)
  return px.seq - py.seq || (px.stream < py.stream ? -1 : px.stream > py.stream ? 1 : 0)
}

/** A sent message's bytes in both runs, paired by the send's own key, and the step key it shows at. */
export interface WirePair { key: string; normal: TraceEvent | null; attacked: TraceEvent | null; at: string }

/**
 * The step key each wire event shows at, from its own side's order: a send shows with the engine event before it on that side (the
 * message it sends), and a receive with the next engine event on that side (the message it reads). '' is the start of the run. A
 * receive with no later engine event has no entry, so it shows at the end.
 */
export function wireSteps(events: readonly TraceEvent[]): Map<TraceEvent, string> {
  const out = new Map<TraceEvent, string>()
  const last = new Map<string, string>()
  const waiting = new Map<string, TraceEvent[]>()
  for (const e of events) {
    if (!e.streamId) continue
    if (!isWire(e)) {
      const key = streamKey(e)
      last.set(e.actor, key)
      for (const w of waiting.get(e.actor) ?? []) out.set(w, key)
      waiting.delete(e.actor)
    } else if (e.type === 'wire.received') waiting.set(e.actor, [...(waiting.get(e.actor) ?? []), e])
    else out.set(e, last.get(e.actor) ?? '')
  }
  return out
}

/**
 * The 2 runs, paired by key, one step per engine-stream key that either run holds. The order of the steps comes from the streams alone:
 * by place in stream, then by stream name. The engine runs client and server on 2 threads, so the order of events across the 2 sides
 * is not the same from one run to the next, and the screen must never take an order from it. Within a stream the order is stable, and
 * the engine streams hold the same events on every run. So one attack run gives the same steps, the same split, and the same count
 * every time (the lead and Richard on #297). Events with no stream id stay out: they belong to no stream, so they cannot pair.
 */
export function pairRuns(normal: readonly TraceEvent[], attacked: readonly TraceEvent[]): RunPair[] {
  return pairing(normal, attacked).pairs
}

/**
 * The engine-stream pairs, the sent-message pairs, and any engine key a run holds twice. With a duplicate the pairs cannot be trusted,
 * and the screen says so. A send is one event per message, so sends pair by key; a receive is one event per socket read, so it never
 * pairs.
 */
export function pairing(normal: readonly TraceEvent[], attacked: readonly TraceEvent[]): { pairs: RunPair[]; wires: WirePair[]; duplicates: string[] } {
  const engine = (e: TraceEvent) => !isWire(e)
  const n = byKey(normal, engine), a = byKey(attacked, engine)
  const keys = [...new Set([...n.map.keys(), ...a.map.keys()])].sort(byPlace)
  const pairs = keys.map(key => {
    const ne = n.map.get(key) ?? null, ae = a.map.get(key) ?? null
    return { key, normal: ne, attacked: ae, changed: !!ne && !!ae && differs(ne, ae) }
  })
  const sent = (e: TraceEvent) => e.type === 'wire.sent'
  const ns = byKey(normal, sent), as = byKey(attacked, sent)
  const nAt = wireSteps(normal), aAt = wireSteps(attacked)
  const wires = [...new Set([...ns.map.keys(), ...as.map.keys()])].sort(byPlace).map(key => {
    const ne = ns.map.get(key) ?? null, ae = as.map.get(key) ?? null
    return { key, normal: ne, attacked: ae, at: (ne && nAt.get(ne)) ?? (ae && aAt.get(ae)) ?? '' }
  })
  return { pairs, wires, duplicates: [...n.duplicates, ...a.duplicates] }
}

/**
 * The first send where the attack changed bytes inside one message: both runs send the same message, with different wire bytes.
 * This is what a byte flip does. -1 when no message changed that way.
 */
export const firstChange = (wires: readonly WirePair[]): number => wires.findIndex(p =>
  !!p.normal && !!p.attacked && p.normal.message === p.attacked.message
  && !!p.normal.wire && !!p.attacked.wire && p.normal.wire !== p.attacked.wire)

/**
 * Where the 2 runs part: the first pair that only one run holds, or where the 2 runs send different messages. A scenario attack
 * (ECB in place of GCM, an old protocol) parts the runs this way, and a caught attack parts them where the attacked run stops.
 * -1 when the runs never part.
 */
export const splitAt = (pairs: readonly RunPair[]): number => pairs.findIndex(p =>
  !p.normal || !p.attacked || p.normal.type !== p.attacked.type || p.normal.message !== p.attacked.message)

/** The byte offsets where 2 wire hex strings differ, over the longer of the 2. */
export function changedBytes(a: string, b: string): number[] {
  const out: number[] = []
  const n = Math.max(a.length, b.length) >> 1
  for (let i = 0; i < n; i++) if (a.slice(2 * i, 2 * i + 2) !== b.slice(2 * i, 2 * i + 2)) out.push(i)
  return out
}

/** A run's result for one check: pass or fail as the engine reported it, or none when the run holds no event for that check. */
export function checkResult(events: readonly TraceEvent[], checkName: string): 'pass' | 'fail' | 'none' {
  if (!checkName) return 'none'
  const hits = events.filter(e => e.check?.name === checkName)
  if (hits.some(e => e.check!.result === 'fail')) return 'fail'
  return hits.length ? 'pass' : 'none'
}
