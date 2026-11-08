import { expect, test } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { PORTS } from './ports'
import { PORT, TOKEN } from './walk'

// The attack index's content (docs/sections-plan.md, slice P3). The list of runs comes from the live Host's registry, never from grep,
// so a run added to the engine and missing here, or a row here for a run the engine dropped, fails this file.
const src = path.join(__dirname, '..', 'src')
interface Row { attackId: string; kind: string; tourStep: string | null; guard: string }
const file = JSON.parse(fs.readFileSync(path.join(src, 'attacks.json'), 'utf8')) as { labels: { id: string; text: string }[]; runs: Row[] }

async function registry(request: import('@playwright/test').APIRequestContext): Promise<string[]> {
  const headers = { Authorization: `Bearer ${TOKEN}`, Origin: `http://localhost:${PORTS.preview}` }
  const all = await request.get(`http://127.0.0.1:${PORT}/api/lessons`, { headers })
  expect(all.ok(), 'the Host answers the lesson list').toBe(true)
  // The list holds every lesson, the toy (lesson 0) included.
  const rows = (await all.json()) as { lesson: number; attacks: { attackId: string }[] }[]
  expect(rows.map(r => r.lesson), 'lessons 0 to 11, in order').toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
  return rows.flatMap(r => r.attacks.map(a => a.attackId))
}

/** The tour step whose action, or whose try-it's action, runs each attack. */
function tourSteps(): Map<string, string> {
  const out = new Map<string, string>()
  for (const f of fs.readdirSync(path.join(src, 'tours')).filter(n => /^lesson-\d+\.json$/.test(n))) {
    const body = JSON.parse(fs.readFileSync(path.join(src, 'tours', f), 'utf8'))
    const steps = (Array.isArray(body) ? body : body.steps ?? []) as { id: string; action?: { type?: string; attackId?: string }; tryIt?: unknown }[]
    for (const s of steps) {
      const tries = (Array.isArray(s.tryIt) ? s.tryIt : s.tryIt ? [s.tryIt] : []) as { action?: { type?: string; attackId?: string } }[]
      for (const a of [s.action, ...tries.map(t => t.action)]) if (a?.type === 'run-attack' && a.attackId && !out.has(a.attackId)) out.set(a.attackId, s.id)
    }
  }
  return out
}

test('the file holds one row for each run the Host registers, no more and no fewer', async ({ request }) => {
  const live = await registry(request)
  const ids = file.runs.map(r => r.attackId)
  expect(new Set(ids).size, 'no run appears twice').toBe(ids.length)
  expect(live.filter(id => !ids.includes(id)), 'registered runs with no row').toEqual([])
  expect(ids.filter(id => !live.includes(id)), 'rows for runs the Host does not register').toEqual([])
  expect(ids.length).toBe(live.length)
})

test('every run has one of the labels, and every label holds at least one run', () => {
  const labels = new Set(file.labels.map(l => l.id))
  expect(file.runs.filter(r => !labels.has(r.kind)).map(r => r.attackId)).toEqual([])
  expect(file.labels.filter(l => !file.runs.some(r => r.kind === l.id)).map(l => l.id)).toEqual([])
})

test('each tourStep names the step that plays the run, and null means no tour plays it', () => {
  const steps = tourSteps()
  const wrong = file.runs.filter(r => (steps.get(r.attackId) ?? null) !== r.tourStep).map(r => `${r.attackId}: file ${r.tourStep}, tours ${steps.get(r.attackId) ?? null}`)
  expect(wrong).toEqual([])
})

test('each run has a readable name under 50 characters, and no two runs in one lesson share a name', () => {
  const runs = file.runs as (Row & { name?: string })[]
  expect(runs.filter(r => !r.name || r.name.trim() === '').map(r => r.attackId), 'runs with no name').toEqual([])
  expect(runs.filter(r => (r.name ?? '').length >= 50).map(r => `${r.attackId}: ${r.name}`), 'names of 50 characters or more').toEqual([])
  expect(runs.filter(r => r.name === r.attackId).map(r => r.attackId), 'names that only repeat the id').toEqual([])
  const lessonOf = (id: string) => id.split('-')[0]
  const seen = new Map<string, string>()
  const clashes: string[] = []
  for (const r of runs) {
    const key = `${lessonOf(r.attackId)} ${r.name}`
    if (seen.has(key)) clashes.push(`${seen.get(key)} and ${r.attackId}: ${r.name}`)
    else seen.set(key, r.attackId)
  }
  expect(clashes, 'two runs in one lesson with one name').toEqual([])
})

test('each guard is one or two short sentences', () => {
  const bad = file.runs.filter(r => {
    const sentences = r.guard.split(/(?<=\.)\s+/).filter(Boolean)
    return !r.guard.endsWith('.') || sentences.length > 2 || sentences.some(s => s.split(/\s+/).length > 25)
  }).map(r => r.attackId)
  expect(bad).toEqual([])
})
