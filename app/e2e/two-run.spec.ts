import { expect, test, type Page } from '@playwright/test'
import { open } from './walk'

// The two-run layout (docs/sections-plan.md item 3; Steve, Q4 A): the normal run beside the attacked run, paired event by event.
// Each case is one kind of run Echo's clauses pick: a byte flip with a catching check, a run that changes how the run goes, and a
// run nothing catches.

async function openRun(page: Page, attackId: string) {
  await open(page)
  await page.getByTestId('attack-index-open').click()
  await page.getByTestId(`attack-row-${attackId}`).click()
  await expect(page.getByTestId('two-run')).toBeVisible({ timeout: 60_000 })
}

test('a caught byte flip: the check passes under the normal run, fails under the attacked run, and the changed bytes are lit', async ({ page }) => {
  await openRun(page, 'L1-flip-gcm')
  await expect(page.getByTestId('two-run-check-normal')).toHaveAttribute('data-result', 'pass', { timeout: 60_000 })
  await expect(page.getByTestId('two-run-check-attacked')).toHaveAttribute('data-result', 'fail', { timeout: 60_000 })
  await expect(page.getByTestId('two-run-check-attacked')).toContainText('GCM tag')
  expect(await page.getByTestId('two-run-diff').locator('[data-changed="true"]').count(), 'the flipped byte is lit').toBeGreaterThan(0)
})

test('a run that changes how the run goes shows where the 2 runs part, and the line stays once both runs finish', async ({ page }) => {
  await openRun(page, 'L1-use-ecb')
  await expect(page.getByTestId('two-run-running'), 'both runs finish').toHaveCount(0, { timeout: 60_000 })
  const split = page.getByTestId('two-run-split')
  await expect(split).toBeVisible()
  // A split read while one run still ran would vanish once it caught up, so the line must still be there after a pause.
  await page.waitForTimeout(1500)
  await expect(split).toBeVisible()
  await expect(split).toContainText('The runs part at step')
  // After the runs part, later messages differ throughout. That is no byte change inside one message, so nothing is lit.
  expect(await page.getByTestId('two-run-diff').locator('[data-changed="true"]').count(), 'no byte is lit for a scenario attack').toBe(0)
})

test('a run nothing catches shows no check result under the attacked run', async ({ page }) => {
  await openRun(page, 'L1-flip-cbc')
  // 'none' is also the reading before a check event arrives, so the result is read only once both runs finish (Jared on #297).
  await expect(page.getByTestId('two-run-running'), 'both runs finish').toHaveCount(0, { timeout: 60_000 })
  await expect(page.getByTestId('two-run-check-attacked')).toHaveAttribute('data-result', 'none')
  await expect(page.getByTestId('two-run-check-attacked')).toContainText('No check catches this attack')
  await expect(page.getByTestId('two-run-check-normal')).toContainText('The normal run has no attack to catch')
})

// The engine runs client and server on 2 threads, so events from the 2 sides arrive in a different order from run to run. The clock
// and the split come from per-stream order only, so one attack opened twice gives the same step count and the same split.
test('one attack opened twice gives the same step count and the same split', async ({ page }) => {
  const reading = async () => {
    await expect(page.getByTestId('two-run-running'), 'both runs finish').toHaveCount(0, { timeout: 60_000 })
    await expect(page.getByTestId('two-run-split')).toBeVisible()
    return { steps: await page.getByTestId('two-run-clock').getAttribute('max'), split: await page.getByTestId('two-run-split').getAttribute('data-at'),
      words: await page.getByTestId('two-run-split').textContent() }
  }
  await openRun(page, 'L1-use-ecb')
  const first = await reading()
  await page.getByTestId('two-run-back').click()
  await page.getByTestId('attack-row-L1-use-ecb').click()
  await expect(page.getByTestId('two-run')).toBeVisible({ timeout: 60_000 })
  const second = await reading()
  expect(second, 'the second run reads the same as the first').toEqual(first)
  expect(Number(first.steps), 'the runs have steps').toBeGreaterThan(1)
})

test('the status bar drops its single-run event count while both runs show', async ({ page }) => {
  await openRun(page, 'L1-flip-gcm')
  await expect(page.getByTestId('status-position')).toHaveCount(0)
  await page.getByTestId('two-run-back').click()
  await page.getByTestId('lesson-item-1').click()
  await expect(page.getByTestId('status-position')).toBeVisible()
})

test('one clock steps both runs, and Back returns to the index with the row kept and focused', async ({ page }) => {
  await openRun(page, 'L1-flip-gcm')
  const clock = page.getByTestId('two-run-clock')
  await expect(page.getByTestId('two-run-check-attacked')).toHaveAttribute('data-result', 'fail', { timeout: 60_000 })
  const end = Number(await clock.getAttribute('max'))
  expect(end, 'the runs have pairs to step').toBeGreaterThan(1)
  await page.getByTestId('two-run-prev').click()
  await expect(clock).toHaveValue(String(end - 1))
  await page.getByTestId('two-run-back').click()
  const row = page.getByTestId('attack-row-L1-flip-gcm')
  await expect(row).toHaveAttribute('data-kept', 'true')
  await expect(row).toBeFocused()
})
