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
 * The pairs, in the normal run's order, with each key the attacked run alone holds placed after the pair before it in the attacked
 * run. Events with no stream id stay out: they belong to no stream, so they cannot pair.
 */
export function pairRuns(normal: readonly TraceEvent[], attacked: readonly TraceEvent[]): RunPair[] {
  const byKey = new Map(attacked.filter(e => e.streamId).map(e => [streamKey(e), e]))
  const pairs: RunPair[] = []
  const used = new Set<string>()
  for (const n of normal) {
    if (!n.streamId) continue
    const key = streamKey(n)
    const a = byKey.get(key) ?? null
    if (a) used.add(key)
    pairs.push({ key, normal: n, attacked: a, changed: !!a && differs(n, a) })
  }
  // Keys only the attacked run holds: insert each after the pair that precedes it in the attacked run.
  let after = -1
  for (const a of attacked) {
    if (!a.streamId) continue
    const key = streamKey(a)
    const at = pairs.findIndex(p => p.key === key)
    if (at >= 0) { after = at; continue }
    if (used.has(key)) continue
    pairs.splice(after + 1, 0, { key, normal: null, attacked: a, changed: false })
    after++
  }
  return pairs
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
