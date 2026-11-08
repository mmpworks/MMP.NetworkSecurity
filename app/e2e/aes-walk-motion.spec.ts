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

test('Next while paused ends the motion and moves on one step', async ({ page }) => {
  await toSubBytes(page)
  await page.getByTestId('aes-walk-next').click()
  await play(page).click()
  await expect(play(page)).toHaveText('Resume')
  await page.getByTestId('aes-walk-next').click()
  await expect(kind(page), 'one press moves on from a paused step').toHaveText('ShiftRows')
  await expect(play(page)).not.toHaveText('Resume')
})
