import { expect, test } from '@playwright/test'
import * as path from 'node:path'
import { runFreePlay, tourIds, walkTour } from './walk'

test('walks every step of lesson 6 against the live Host', async ({ page }) => {
  const visited = await walkTour(page, 6, path.join(__dirname, '..', 'test-results', 'lesson-6'))
  expect(visited).toEqual(tourIds(6))
})

test('lesson 6 shows erased rungs and reads the register count from the event', async ({ page }) => {
  await runFreePlay(page, 6)
  await page.getByTestId('inspector-tab-ladder').click()
  expect(await page.locator('[data-testid^="key-rung-erased-"]').count(), 'erased rungs').toBeGreaterThan(0)
  await expect(page.getByTestId('reader-registers')).toContainText(/\d+ held, next counter \d+/)
})

test('lesson 6 replayed sale is caught by KSN already seen', async ({ page }) => {
  await runFreePlay(page, 6)
  await page.getByTestId('attack-L6-replay-sale').click()
  await expect(page.getByTestId('attack-result')).toContainText('KSN already seen')
})
