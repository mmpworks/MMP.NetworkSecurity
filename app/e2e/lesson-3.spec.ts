import { expect, test } from '@playwright/test'
import * as path from 'node:path'
import { runFreePlay, tourIds, walkTour } from './walk'

test('walks every step of lesson 3 against the live Host', async ({ page }) => {
  const visited = await walkTour(page, 3, path.join(__dirname, '..', 'test-results', 'lesson-3'))
  expect(visited).toEqual(tourIds(3))
})

test('lesson 3 shows both sides holding the same secret, and the hybrid secret as 64 cells', async ({ page }) => {
  await runFreePlay(page, 3)
  await expect(page.getByTestId('convergence-match').first()).toBeVisible()
  await expect(page.getByTestId('secret-row-client-hybrid.shared')).toBeVisible()
  await expect(page.getByTestId('secret-row-server-hybrid.shared')).toBeVisible()
  const cells = await page.locator('[data-testid=convergence-grid-client]').last().locator('.cell').count()
  expect(cells, 'cells in the last convergence grid of the client').toBe(64)
})

test('lesson 3 ML-KEM tamper: the confirmation MAC names the catch', async ({ page }) => {
  await runFreePlay(page, 3)
  await page.getByTestId('attack-L3-flip-mlkem-ciphertext').click()
  await expect(page.getByTestId('attack-result')).toContainText('key confirmation MAC')
})
