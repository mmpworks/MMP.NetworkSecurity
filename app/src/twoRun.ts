// The two-run layout's pairing (docs/sections-plan.md item 3, notes 3 to 5; Steve, Q4 A). Pure, so a spec can call it.
// An attack is a fork: the Host reruns the lesson with the parent's seed and the attack's plan. So the normal run and the attacked
// run pair event by event on (stream, place in stream) until the attack changes the run.
import type { TraceEvent } from './types'

export interface RunPair { key: string; normal: TraceEvent | null; attacked: TraceEvent | null; changed: boolean }

/** The stream key without the session id, which differs between the 2 runs: "<session>/client/aes" pairs as "client/aes". */
export const streamKey = (e: TraceEvent): string => `${e.streamId.split('/').slice(1).join('/')}#${e.streamSeq}`

/** Two events at one key differ when their type, message or wire bytes differ. */
const differs = (a: TraceEvent, b: TraceEvent): boolean => a.type !== b.type || a.message !== b.message || a.wire !== b.wire

/** A run's events by key. A key held twice is a stream opened twice, which pairing by stream cannot tell apart, so it is reported. */
function byKey(events: readonly TraceEvent[]): { map: Map<string, TraceEvent>; duplicates: string[] } {
  const map = new Map<string, TraceEvent>()
  const duplicates: string[] = []
  for (const e of events) {
    if (!e.streamId) continue
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

/**
 * The 2 runs, paired by key, one step per key that either run holds. The order of the steps comes from the streams alone: by place in
 * stream, then by stream name. The engine runs client and server on 2 threads, so the order of events across the 2 sides is not the
 * same from one run to the next, and the screen must never take an order from it. Within a stream the order is stable. So one attack
 * run gives the same steps, the same split, and the same count every time (the lead and Richard on #297).
 * Events with no stream id stay out: they belong to no stream, so they cannot pair.
 */
export function pairRuns(normal: readonly TraceEvent[], attacked: readonly TraceEvent[]): RunPair[] {
  return pairing(normal, attacked).pairs
}

/** The pairs, and any key a run holds twice. With a duplicate the pairs cannot be trusted, and the screen says so. */
export function pairing(normal: readonly TraceEvent[], attacked: readonly TraceEvent[]): { pairs: RunPair[]; duplicates: string[] } {
  const n = byKey(normal), a = byKey(attacked)
  const keys = [...new Set([...n.map.keys(), ...a.map.keys()])].sort((x, y) => {
    const px = parts(x), py = parts(y)
    return px.seq - py.seq || (px.stream < py.stream ? -1 : px.stream > py.stream ? 1 : 0)
  })
  const pairs = keys.map(key => {
    const ne = n.map.get(key) ?? null, ae = a.map.get(key) ?? null
    return { key, normal: ne, attacked: ae, changed: !!ne && !!ae && differs(ne, ae) }
  })
  return { pairs, duplicates: [...n.duplicates, ...a.duplicates] }
}

/**
 * The first pair where the attack changed bytes inside one message: both runs send the same message, with different wire bytes.
 * This is what a byte flip does. -1 when no message changed that way.
 */
export const firstChange = (pairs: readonly RunPair[]): number => pairs.findIndex(p =>
  !!p.normal && !!p.attacked && p.normal.type === p.attacked.type && p.normal.message === p.attacked.message
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
