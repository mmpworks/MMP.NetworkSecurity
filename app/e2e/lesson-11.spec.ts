import { expect, test } from '@playwright/test'
import * as path from 'node:path'
import { isBuilt, runFreePlay, tourIds, walkTour } from './walk'

// Lesson 11 is built, so each test first asserts that the Host lists it as built. A change that stops building it fails here, never as a skip.
test.beforeEach(async () => { expect(await isBuilt(11), 'LESSON_NOT_BUILT: the Host lists lesson 11 as not built').toBe(true) })

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
  // The leaky half: no check catches it, and the timing tab shows the guess recovered every secret byte (the engine's own check needs all).
  await runFreePlay(page, 11)
  await page.getByTestId('attack-L11-guess-leaky').click()
  await expect(page.getByTestId('attack-result')).toContainText('The session ended', { timeout: 90_000 })
  await expect(page.getByTestId('attack-result')).toContainText('completed')
  await expect(page.getByTestId('attack-result').getByTestId('check-name')).toHaveCount(0)
  await page.getByTestId('inspector-tab-timing').click()
  const found = ((await page.getByTestId('timing-guess-leaky').getByTestId('guess-result').textContent()) ?? '').match(/(?<got>\d+) of (?<all>\d+) secret bytes found/)
  expect(found?.groups, 'the leaky guess card names its bytes found').toBeTruthy()
  expect(Number(found!.groups!.all)).toBeGreaterThan(0)
  expect(found!.groups!.got, 'the leaky guess recovers every secret byte').toBe(found!.groups!.all)
  // The constant-time half: the check stops the guess.
  await runFreePlay(page, 11)
  await page.getByTestId('attack-L11-guess-constant-time').click()
  await expect(page.getByTestId('attack-result')).toContainText('constant-time compare')
})
