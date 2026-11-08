import { expect, test, type Page } from '@playwright/test'
import { runFreePlay } from './walk'

// The walk's motion and its one clock (docs/walkthrough-design.md section 2.2a, Steve's pause rule). The acceptance clauses cover
// reduced motion, Play's stop and a flip during Play. These cover Pause, Resume and Back, which no clause reads.

const kind = (page: Page) => page.getByTestId('aes-walk-step-kind')
const play = (page: Page) => page.getByTestId('aes-walk-play')
/** Running and paused walk motions under the walk's root. A button's own CSS transition is not a walk motion, so it is left out. */
const motion = (page: Page) => page.getByTestId('aes-walk-block').evaluate(el => {
  const all = el.getAnimations({ subtree: true }).filter(a => !(a instanceof CSSTransition) && !(a instanceof CSSAnimation))
  return { running: all.filter(a => a.playState === 'running').length, paused: all.filter(a => a.playState === 'paused').length }
})

async function toSubBytes(page: Page) {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await runFreePlay(page, 1)
  await page.getByTestId('aes-walk-tab').click()
  for (let i = 0; i < 80 && (await kind(page).textContent())?.trim() !== 'AddRoundKey'; i++) await page.getByTestId('aes-walk-next').click()
  await page.emulateMedia({ reducedMotion: 'no-preference' })
}

test('Pause freezes a running step in place, and Resume finishes it from there', async ({ page }) => {
  await toSubBytes(page)
  await page.getByTestId('aes-walk-next').click()
  await expect(kind(page)).toHaveText('SubBytes')
  await expect(play(page), 'one Next makes the button read Pause').toHaveText('Pause')
  await play(page).click()
  await expect(play(page)).toHaveText('Resume')
  const frozen = await motion(page)
  expect(frozen.running, 'nothing moves while paused').toBe(0)
  expect(frozen.paused, 'the motion is held, not ended').toBeGreaterThan(0)
  await page.waitForTimeout(700)
  expect((await motion(page)).paused, 'it stays held').toBe(frozen.paused)
  await play(page).click()
  await expect.poll(async () => (await motion(page)).running + (await motion(page)).paused, { message: 'Resume carries the motion to its end', timeout: 10_000 }).toBe(0)
  await expect(play(page)).toHaveText('Play')
  await expect(kind(page), 'Resume does not move to another step').toHaveText('SubBytes')
})

test('Back during a motion lands on the step before, with no old-byte mark and nothing moving', async ({ page }) => {
  await toSubBytes(page)
  await page.getByTestId('aes-walk-next').click()
  await expect.poll(async () => (await motion(page)).running, { timeout: 2_000, intervals: [20] }).toBeGreaterThan(0)
  await page.getByTestId('aes-walk-back').click()
  await expect(kind(page)).toHaveText('AddRoundKey')
  expect(await page.locator('[data-testid^="aes-walk-cell-"][data-old]').count(), 'no old-byte mark is left').toBe(0)
  const after = await motion(page)
  expect(after.running + after.paused, 'nothing moves after Back').toBe(0)
})

test('through the ShiftRows roll, every column of every moving row shows a byte', async ({ page }) => {
  await toSubBytes(page)
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.getByTestId('aes-walk-next').click()
  await expect(kind(page)).toHaveText('SubBytes')
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  await page.getByTestId('aes-walk-next').click()
  await expect(kind(page)).toHaveText('ShiftRows')
  await play(page).click()
  await expect(play(page)).toHaveText('Resume')
  // The point checks find a cell, or the old-byte layer riding on it, and a gap hits the grid behind them. The layer takes no click in
  // the app, so this test lets the probe hit it.
  await page.addStyleTag({ content: '.aw-cell[data-old]::after { pointer-events: auto !important; }' })
  // The probe runs at 25%, 50% and 80% of each row's roll. A hole can open late, as a neighbour cell settles, so one time is not enough.
  const holes = await page.getByTestId('aes-walk-block').evaluate(el => {
    const missing: string[] = []
    for (const at of [0.25, 0.5, 0.8]) {
    for (const a of el.getAnimations({ subtree: true })) {
      if (a instanceof CSSTransition || a instanceof CSSAnimation) continue
      const t = a.effect!.getTiming()
      a.currentTime = Number(t.delay ?? 0) + Number(t.duration) * at
    }
    for (const r of [1, 2, 3]) for (const c of [0, 1, 2, 3]) {
      const col = el.querySelector(`[data-testid="aes-walk-cell-0-${c}"]`)!.getBoundingClientRect()
      const row = el.querySelector(`[data-testid="aes-walk-cell-${r}-0"]`)!.getBoundingClientRect()
      // 3 points across the column: a half-column offset can put the centre in the thin gap between 2 cells, and a real hole is a whole cell wide.
      const y = row.top + row.height / 2
      const hits = [-0.25, 0, 0.25].map(f => document.elementFromPoint(col.left + col.width * (0.5 + f), y)?.closest('[data-testid^="aes-walk-cell-"]'))
      if (!hits.some(Boolean)) missing.push(`${at * 100}%: row ${r}, column ${c}`)
    }
    }
    return missing
  })
  expect(holes, 'no empty slot mid-roll').toEqual([])
})

test('Next while paused ends the motion and moves on one step', async ({ page }) => {
  await toSubBytes(page)
  await page.getByTestId('aes-walk-next').click()
  await play(page).click()
  await expect(play(page)).toHaveText('Resume')
  await page.getByTestId('aes-walk-next').click()
  await expect(kind(page), 'one press moves on from a paused step').toHaveText('ShiftRows')
  await expect(play(page)).not.toHaveText('Resume')
})
