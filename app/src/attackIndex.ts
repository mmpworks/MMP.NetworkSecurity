// The attack index (docs/sections-plan.md item 3, slice P3). Pure, so a spec can call it.
// The Host's lesson list says which runs exist, their lesson, and the check that catches each one. attacks.json adds only what the
// Host does not hold: the kind (the group on screen), the tour step that plays the run, and the guard sentence.
import data from './attacks.json'
import type { LessonRow } from './types'

export interface AttackLabel { id: string; text: string }
export interface AttackEntry {
  attackId: string
  lesson: number
  /** The Host's name for the run. */
  name: string
  /** The check that catches the run, from the Host. Empty when nothing catches it. */
  check: string
  code: string
  kind: string
  tourStep: string | null
  guard: string
}
export interface AttackGroup { label: AttackLabel; rows: AttackEntry[] }

/** `name` is optional: a readable name for the row, when attacks.json gives one. Without it the row shows the Host's label. */
interface JsonRun { attackId: string; kind: string; tourStep: string | null; guard: string; name?: string }

/** The group for a run the Host registers and attacks.json does not list yet, so no run goes without a group (sections-plan item 3). */
export const UNLISTED: AttackLabel = { id: 'unlisted', text: 'not in the index file yet' }

export const LABELS: AttackLabel[] = (data as { labels: AttackLabel[] }).labels

/**
 * One row per run the Host registers, grouped in the label order of attacks.json. A group with no run does not show. A run that
 * attacks.json does not list goes in UNLISTED, at the end. A row of attacks.json that the Host does not register is left out.
 */
export function attackGroups(lessons: readonly LessonRow[], runs: readonly JsonRun[] = (data as { runs: JsonRun[] }).runs): AttackGroup[] {
  const byId = new Map(runs.map(r => [r.attackId, r]))
  const entries: AttackEntry[] = lessons.flatMap(l => l.attacks.map(a => {
    const j = byId.get(a.attackId)
    return {
      attackId: a.attackId, lesson: l.lesson, name: j?.name ?? a.label, check: a.expectCheck ?? '', code: a.expectCode ?? '',
      kind: j && LABELS.some(x => x.id === j.kind) ? j.kind : UNLISTED.id, tourStep: j?.tourStep ?? null, guard: j?.guard ?? '',
    }
  }))
  return [...LABELS, UNLISTED]
    .map(label => ({ label, rows: entries.filter(e => e.kind === label.id) }))
    .filter(g => g.rows.length > 0)
}

/** How many runs the index lists, which must equal the Host's count (the kill condition's 57 of 57). */
export const runCount = (groups: readonly AttackGroup[]): number => groups.reduce((n, g) => n + g.rows.length, 0)
