import { expect, test, type Page } from '@playwright/test'
import { PORTS } from './ports'
import { TOKEN, open } from './walk'

// The attack index (docs/sections-plan.md item 3; kill condition: every registered attack run is reachable from the index, and each
// plays its run). The Host's lesson list is the count to meet, so a new run on the Host fails here until the index lists it.

interface HostRun { lesson: number; attackId: string; label: string; expectCheck?: string }

async function hostRuns(): Promise<HostRun[]> {
  const r = await fetch(`http://127.0.0.1:${PORTS.host}/api/lessons`, { headers: { Authorization: `Bearer ${TOKEN}` } })
  const body: any = await r.json()
  const rows: any[] = Array.isArray(body) ? body : body?.lessons ?? []
  const runs = rows.flatMap(l => (l.attacks ?? []).map((a: any) => ({ lesson: l.lesson, attackId: String(a.attackId ?? a.id ?? a), label: String(a.label ?? a.attackId ?? a), expectCheck: a.expectCheck })))
  // Lesson 0 is the toy, which the Host's list leaves out and the app adds with its one run (store.ts TOY_LESSON).
  return [{ lesson: 0, attackId: 'L0-flip-wire-byte', label: 'Flip a byte on the wire', expectCheck: 'echo compare' }, ...runs]
}

async function openIndex(page: Page) {
  await open(page)
  await page.getByTestId('attack-index-open').click()
  await expect(page.getByTestId('attack-index')).toBeVisible()
}

test('the index lists every attack run the Host registers, once, in a group, with its lesson and its check', async ({ page }) => {
  const runs = await hostRuns()
  await openIndex(page)
  const rows = page.locator('[data-testid^="attack-row-"][data-kind]')
  await expect(rows, 'one row per registered run').toHaveCount(runs.length)
  await expect(page.getByTestId('attack-index-count')).toContainText(`${runs.length} attack runs`)
  expect(await page.locator('[data-testid="attack-group-unlisted"]').count(), 'every run has a group from attacks.json').toBe(0)
  for (const run of runs) {
    const row = page.getByTestId(`attack-row-${run.attackId}`)
    await expect(row, run.attackId).toHaveAttribute('data-lesson', String(run.lesson))
    // The row shows its attack id, as its name or as the small line under a readable name, and its name is never empty.
    await expect(row, run.attackId).toContainText(run.attackId)
    await expect(row.getByTestId('attack-row-name'), run.attackId).not.toHaveText('')
    if (run.expectCheck) await expect(row.getByTestId('attack-row-check'), run.attackId).toContainText(run.expectCheck)
  }
})

test('the L7 recording row carries the guard words agreed for it', async ({ page }) => {
  await openIndex(page)
  await expect(page.getByTestId('attack-row-L7-decrypt-recording').getByTestId('attack-row-guard')).toHaveText(
    'A stolen server key opens a recorded RSA session. The same key opens nothing on ECDHE, because neither side stores the private halves of the shares that made its keys.')
})

// All registered runs take about 7 minutes, so the default suite plays the first run of each group, and NETSEC_SWEEP_ALL=1 plays all
// of them, as the Eavesdropper sweep rule does (eavesdropper-sweep.spec.ts). The kill condition's 57 of 57 is checked with it set.
const ALL = process.env.NETSEC_SWEEP_ALL === '1'

test(`${ALL ? 'every row' : 'the first row of each group'} plays its run in its lesson, and Back returns to that row`, async ({ page }) => {
  test.setTimeout(20 * 60_000)
  const all = await hostRuns()
  await openIndex(page)
  const firsts = await page.locator('[data-testid^="attack-group-"]').evaluateAll(gs => gs.map(g => g.querySelector('[data-testid^="attack-row-"]')?.getAttribute('data-testid')?.slice('attack-row-'.length) ?? ''))
  const runs = ALL ? all : all.filter(r => firsts.includes(r.attackId))
  const played: string[] = []
  for (const run of runs) {
    if (!(await page.getByTestId('attack-index').isVisible())) await page.getByTestId('attack-index-open').click()
    await page.getByTestId(`attack-row-${run.attackId}`).click()
    // The fork shows its own result panel, titled "attack: <attackId>" by the Host.
    const result = page.getByTestId('attack-result')
    await expect(result, `${run.attackId} plays`).toBeVisible({ timeout: 60_000 })
    await expect(result, `${run.attackId} is the run that played`).toContainText(`attack: ${run.attackId}`, { timeout: 60_000 })
    await expect(page.getByTestId(`lesson-item-${run.lesson}`), `${run.attackId} opens lesson ${run.lesson}`).toHaveAttribute('aria-current', 'true')
    played.push(run.attackId)
    await page.getByTestId('attack-back-to-index').click()
    await expect(page.getByTestId(`attack-row-${run.attackId}`), `Back keeps ${run.attackId}`).toHaveAttribute('data-kept', 'true')
  }
  expect(played.length, ALL ? 'every registered run played' : 'the first run of every group played').toBe(runs.length)
  if (ALL) expect(played.length, 'all registered runs').toBe(all.length)
})
