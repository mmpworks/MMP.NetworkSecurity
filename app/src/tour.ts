import type { GlossaryTerm, TourStep, TraceEvent, ViewMode } from './types'

// Pure tour logic. No Vue, no sockets: a test can call every function here.

const tourFiles = import.meta.glob('./tours/lesson-*.json', { eager: true, import: 'default' }) as Record<string, unknown>
const glossaryFiles = import.meta.glob('./glossary.json', { eager: true, import: 'default' }) as Record<string, unknown>

export function toursByLesson(files: Record<string, unknown> = tourFiles): Map<number, TourStep[]> {
  const out = new Map<number, TourStep[]>()
  for (const [path, body] of Object.entries(files)) {
    const m = /lesson-(?<n>\d+)\.json$/.exec(path)
    if (!m?.groups) continue
    const steps = Array.isArray(body) ? body : (body as { steps?: TourStep[] })?.steps ?? []
    out.set(Number(m.groups.n), [...steps].sort((a, b) => (a.order ?? 0) - (b.order ?? 0) || 0))
  }
  return out
}

export function glossaryById(files: Record<string, unknown> = glossaryFiles): Map<string, GlossaryTerm> {
  const out = new Map<string, GlossaryTerm>()
  for (const body of Object.values(files)) {
    const list = Array.isArray(body) ? body : (body as { terms?: GlossaryTerm[] })?.terms ?? []
    for (const t of list as GlossaryTerm[]) out.set(t.id, t)
  }
  return out
}

export const TOURS = toursByLesson()
export const GLOSSARY = glossaryById()

/** True when the event is the one a step waits on: the event type, plus every field of `match`. */
export function matchesBind(step: TourStep, e: TraceEvent): boolean {
  if (step.bind.kind !== 'event') return false
  const b = step.bind
  if (b.eventType && b.eventType !== e.type) return false
  const m = b.match ?? {}
  if (m.actor && m.actor !== e.actor) return false
  if (m.message && m.message !== e.message) return false
  if (m.step && m.step !== e.step) return false
  return true
}

/** Index of the first matching event at or after `from`, or -1. */
export function findBound(step: TourStep, events: readonly TraceEvent[], from: number): number {
  for (let i = Math.max(0, from); i < events.length; i++) if (matchesBind(step, events[i])) return i
  return -1
}

export interface UnlockContext {
  boundIndex: number
  events: readonly TraceEvent[]
  view: ViewMode
  selectedSeq: number | null
  actionDone: boolean
  /** Outcome the active session ended with (completed, caught), or empty while it runs. */
  outcome: string
  /** The check a caught attack fork ended on, from session.finished. It can differ from the first failed check event (a peer may report PEER_CLOSED_EARLY first). */
  caughtCheck: string
  /** Events that arrived after the step's try-it started. */
  eventsSinceTryIt: readonly TraceEvent[]
}

export interface Unlock { open: boolean; reason: string }

/** What must happen before Next enables (ux-design.md section 3.1 `unlock`). A closed unlock always names its reason. */
export function evaluateUnlock(step: TourStep, ctx: UnlockContext): Unlock {
  const mode = step.unlock?.mode ?? (step.bind.kind === 'event' ? 'event' : 'ack')
  switch (mode) {
    case 'ack':
      return { open: true, reason: '' }
    case 'event':
      return ctx.boundIndex >= 0 ? { open: true, reason: '' } : { open: false, reason: 'Waiting for the engine to send this message' }
    case 'action': {
      if (step.tryIt && expectationMet(step, ctx)) return { open: true, reason: '' }
      return { open: false, reason: 'Do the try-it first' }
    }
    case 'check': {
      const want = step.unlock?.name
      const hit = ctx.eventsSinceTryIt.concat(ctx.events).some(e => e.check && (!want || e.check.name === want) && (!step.unlock?.result || e.check.result === step.unlock.result))
      return hit ? { open: true, reason: '' } : { open: false, reason: want ? `Waiting for the check named ${want}` : 'Waiting for a check result' }
    }
  }
}

export function expectationMet(step: TourStep, ctx: UnlockContext): boolean {
  const x = step.tryIt?.expect
  if (!x) return true
  switch (x.type) {
    case 'view': return ctx.view === x.value
    case 'check': return (x.result !== 'pass' && !!x.name && ctx.caughtCheck === x.name) || ctx.eventsSinceTryIt.some(e => e.check && (!x.name || e.check.name === x.name) && (!x.result || e.check.result === x.result))
    case 'selected': return ctx.selectedSeq != null
    case 'ran': return ctx.actionDone
    case 'attack-outcome': return ctx.outcome !== '' && ctx.outcome === (x.outcome ?? 'completed')
  }
}

// Tour text marks glossary terms as {{term:id}} (ux-design.md section 5).
export type TextSegment = { kind: 'text'; text: string } | { kind: 'term'; id: string; text: string }

export function splitText(text: string): TextSegment[] {
  const out: TextSegment[] = []
  const seen = new Set<string>()
  const re = /\{\{term:(?<id>[a-z0-9-]+)(?:\|(?<label>[^}]*))?\}\}/g
  let last = 0
  for (const m of text.matchAll(re)) {
    const at = m.index ?? 0
    if (at > last) out.push({ kind: 'text', text: text.slice(last, at) })
    const id = m.groups!.id
    const label = m.groups!.label ?? GLOSSARY.get(id)?.term ?? id
    // Only the first use of a term in a step gets the underline.
    if (seen.has(id)) out.push({ kind: 'text', text: label })
    else { seen.add(id); out.push({ kind: 'term', id, text: label }) }
    last = at + m[0].length
  }
  if (last < text.length) out.push({ kind: 'text', text: text.slice(last) })
  return out
}

// Highlight grammar: <panel>:<kind>=<name>
export interface Highlight { panel: string; kind: string; name: string }

export function parseHighlight(s: string): Highlight | null {
  const m = /^(?<panel>[a-z]+):(?<kind>[a-z-]+)=(?<name>.+)$/.exec(s)
  return m?.groups ? { panel: m.groups.panel, kind: m.groups.kind, name: m.groups.name } : null
}
