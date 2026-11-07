import { expect, type Page } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'

// Shared by the lesson specs. Each walk runs against a real Host (playwright.config.ts) and the tour file of the lesson.
export const PORT = 5190
export const TOKEN = 'lesson0-token'

export function tourIds(lesson: number): string[] {
  const f = path.join(__dirname, '..', 'src', 'tours', `lesson-${String(lesson).padStart(2, '0')}.json`)
  const j = JSON.parse(fs.readFileSync(f, 'utf8'))
  return (Array.isArray(j) ? j : j.steps).map((s: { id: string }) => s.id)
}

export interface HostAddress { port: number; token: string }

export async function open(page: Page, host: HostAddress = { port: PORT, token: TOKEN }) {
  await page.addInitScript(({ port, token }) => { (window as any).netsec = { host: { port, token } } }, host)
  await page.goto(`/?port=${host.port}&token=${host.token}`)
  await expect(page.getByTestId('host-chip')).toContainText(/connected/i)
}

/**
 * Walks the running tour with Next until a step shows what a spec needs, so a tour rewrite cannot leave a spec on the wrong step.
 * It does each try-it on the way. When no step within the cap shows it, the spec fails in seconds and names what was missing.
 */
export async function walkTourUntil(page: Page, what: string, shows: () => Promise<boolean>, hops = 15) {
  for (let i = 0; i < hops; i++) {
    if (await shows()) return
    const next = page.getByTestId('tour-next')
    if (await next.isDisabled()) { const t = page.getByTestId('tour-try-it-action'); if (await t.isVisible()) await t.click() }
    await expect(next).toBeEnabled()
    await next.click()
    await page.waitForTimeout(300)
  }
  if (!(await shows())) throw new Error(`no tour step within ${hops} hops shows ${what}`)
}

export async function startTour(page: Page, lesson: number) {
  await open(page)
  await page.getByTestId(`lesson-item-${lesson}`).click()
  await page.getByRole('button', { name: /start tour/i }).click()
}

/** Walks every step. A step with a try-it needs its action before Next enables. Returns the ids the app showed. */
export async function walkTour(page: Page, lesson: number, shots?: string): Promise<string[]> {
  const ids = tourIds(lesson)
  expect(ids.length, `tour steps of lesson ${lesson}`).toBeGreaterThan(0)
  if (shots) fs.mkdirSync(shots, { recursive: true })
  await startTour(page, lesson)
  const visited: string[] = []
  for (let i = 0; i < ids.length; i++) {
    await expect(page.getByTestId('tour-step-id')).toHaveText(ids[i], { timeout: 30_000 })
    visited.push(ids[i])
    await expect(page.getByTestId('error-banner')).toHaveCount(0)
    if (shots) await page.screenshot({ path: path.join(shots, `${ids[i]}.png`) })
    const next = page.getByTestId('tour-next')
    if (await next.isDisabled()) {
      const tryIt = page.getByTestId('tour-try-it-action')
      if (await tryIt.isVisible()) await tryIt.click()
    }
    const reason = await page.getByTestId('next-reason').textContent({ timeout: 500 }).catch(() => '')
    await expect(next, `Next never enabled at ${ids[i]}; reason: ${reason}`).toBeEnabled({ timeout: 45_000 })
    if (i < ids.length - 1) await next.click()
  }
  return visited
}

/** Free play of the whole lesson: start, run to the end, wait for the last event. */
export async function runFreePlay(page: Page, lesson: number) {
  await open(page)
  await page.getByTestId(`lesson-item-${lesson}`).click()
  await page.getByTestId('mode-free').click()
  await page.getByTestId('free-start').click()
  await page.getByTestId('free-run').click()
  await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 60_000 })
}

/** True when the Host lists the lesson as built. A spec for an unbuilt lesson skips with a named reason and never passes. */
export async function isBuilt(lesson: number): Promise<boolean> {
  const r = await fetch(`http://127.0.0.1:${PORT}/api/lessons`, { headers: { Authorization: `Bearer ${TOKEN}` } })
  const body: any = await r.json()
  const rows: any[] = Array.isArray(body) ? body : body?.lessons ?? []
  return !!rows.find(x => x.lesson === lesson)?.built
}
