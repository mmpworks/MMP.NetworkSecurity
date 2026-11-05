import { expect, test } from '@playwright/test'
import * as path from 'node:path'
import { runFreePlay, tourIds, walkTour } from './walk'

test('walks every step of lesson 1 against the live Host', async ({ page }) => {
  const visited = await walkTour(page, 1, path.join(__dirname, '..', 'test-results', 'lesson-1'))
  expect(visited).toEqual(tourIds(1))
})

test('lesson 1 shows the same picture clear and locked, and the ECB leak is a measured number', async ({ page }) => {
  await runFreePlay(page, 1)
  await page.locator('[data-testid^=diagram-message-]', { hasText: 'PictureEcb' }).click()
  await expect(page.getByTestId('picture-clear')).toBeVisible()
  await expect(page.getByTestId('picture-locked')).toBeVisible()
  await expect(page.getByTestId('picture-repeats')).toContainText(/\d+ of \d+ locked blocks repeat/)
  const repeatsEcb = Number(((await page.getByTestId('picture-repeats').textContent()) ?? '').match(/^\s*(\d+)/)?.[1])
  expect(repeatsEcb, 'ECB repeats').toBeGreaterThan(0)
  await page.locator('[data-testid^=diagram-message-]', { hasText: 'PictureCbc' }).click()
  await expect(page.getByTestId('picture-repeats')).toContainText(/^\s*0 of/)
  await page.getByTestId('view-eavesdropper').click()
  await expect(page.getByTestId('picture-clear')).toHaveCount(0)
  await expect(page.getByTestId('picture-locked')).toBeVisible()
})

test('lesson 1 attack on GCM names the check that caught it', async ({ page }) => {
  await runFreePlay(page, 1)
  await page.getByTestId('attack-L1-flip-gcm').click()
  await expect(page.getByTestId('attack-result')).toContainText('GCM tag')
})
