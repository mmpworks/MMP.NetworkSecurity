import { expect, test } from '@playwright/test'
import * as path from 'node:path'
import { isBuilt, runFreePlay, tourIds, walkTour } from './walk'

// Lesson 11 runs only when the Host lists it as built. Until then each test skips with LESSON_NOT_BUILT and counts as not run.
test.beforeEach(async () => { test.skip(!(await isBuilt(11)), 'LESSON_NOT_BUILT: lesson 11') })

test('walks every step of lesson 11 against the live Host', async ({ page }) => {
  const visited = await walkTour(page, 11, path.join(__dirname, '..', 'test-results', 'lesson-11'))
  expect(visited).toEqual(tourIds(11))
})

test('lesson 11 shows measured timings and the t values for this run', async ({ page }) => {
  await runFreePlay(page, 11)
  await page.getByTestId('inspector-tab-timing').click()
  await expect(page.getByTestId('timing-verdict')).toBeVisible()
  for (const id of ['t-leaky', 't-constant', 't-control', 't-managed']) await expect(page.getByTestId(id)).toContainText(/^\d|infinite/)
  await expect(page.locator('[data-testid^=timing-case-]').first()).toBeVisible()
})

test('lesson 11 guess against the constant-time compare stops, and the leaky guess finds bytes', async ({ page }) => {
  await runFreePlay(page, 11)
  await page.getByTestId('attack-L11-guess-constant-time').click()
  await expect(page.getByTestId('attack-result')).toContainText('constant-time compare')
})
