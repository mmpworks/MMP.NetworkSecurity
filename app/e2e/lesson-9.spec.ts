import { expect, test } from '@playwright/test'
import * as path from 'node:path'
import { isBuilt, runFreePlay, tourIds, walkTour } from './walk'

// Lesson 9 is built, so each test first asserts that the Host lists it as built. A change that stops building it fails here, never as a skip.
test.beforeEach(async () => { expect(await isBuilt(9), 'LESSON_NOT_BUILT: the Host lists lesson 9 as not built').toBe(true) })

test('walks every step of lesson 9 against the live Host', async ({ page }) => {
  const visited = await walkTour(page, 9, path.join(__dirname, '..', 'test-results', 'lesson-9'))
  expect(visited).toEqual(tourIds(9))
})

test('lesson 9 onion: the inner PIN block stays closed at the gateway and opens only at the bank', async ({ page }) => {
  await runFreePlay(page, 9)
  await page.getByTestId('inspector-tab-onion').click()
  await expect(page.getByTestId('onion-layer-2')).toHaveAttribute('data-state', 'open')
  await expect(page.getByTestId('onion-layer-1')).toHaveAttribute('data-state', 'open')
  await expect(page.getByTestId('onion-gateway-note')).toContainText('gateway cannot open this')
})

test('lesson 9 flipped PIN block passes both hops and is refused only by the bank check', async ({ page }) => {
  await runFreePlay(page, 9)
  await page.getByTestId('attack-L9-flip-pin-block').click()
  await expect(page.getByTestId('attack-result')).toContainText('PIN block MAC at bank')
  await page.getByTestId('inspector-tab-onion').click()
  await expect(page.getByTestId('onion-layer-1')).toHaveAttribute('data-state', 'broken')
})
