import { expect, test } from '@playwright/test'
import * as path from 'node:path'
import { isBuilt, runFreePlay, tourIds, walkTour } from './walk'

// Lesson 10 is built, so each test first asserts that the Host lists it as built. A change that stops building it fails here, never as a skip.
test.beforeEach(async () => { expect(await isBuilt(10), 'LESSON_NOT_BUILT: the Host lists lesson 10 as not built').toBe(true) })

test('walks every step of lesson 10 against the live Host', async ({ page }) => {
  const visited = await walkTour(page, 10, path.join(__dirname, '..', 'test-results', 'lesson-10'))
  expect(visited).toEqual(tourIds(10))
})

test('lesson 10 splits the token into three parts and reads its claims in words', async ({ page }) => {
  await runFreePlay(page, 10)
  await page.getByTestId('inspector-tab-token').click()
  await page.locator('[data-testid^=diagram-message-]', { hasText: 'TokenIssued' }).click()
  await expect(page.getByTestId('token-token-header')).toBeVisible()
  await expect(page.getByTestId('token-token-claims')).toBeVisible()
  await expect(page.getByTestId('token-token-signature')).toBeVisible()
})

test('lesson 10 changed token claim is caught by the token signature check', async ({ page }) => {
  await runFreePlay(page, 10)
  await page.getByTestId('attack-L10-change-token-claim').click()
  await expect(page.getByTestId('attack-result')).toContainText('token signature')
})
