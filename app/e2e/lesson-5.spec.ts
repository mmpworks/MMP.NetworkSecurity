import { expect, test } from '@playwright/test'
import * as path from 'node:path'
import { runFreePlay, tourIds, walkTour } from './walk'

test('walks every step of lesson 5 against the live Host', async ({ page }) => {
  const visited = await walkTour(page, 5, path.join(__dirname, '..', 'test-results', 'lesson-5'))
  expect(visited).toEqual(tourIds(5))
})

test('lesson 5 lists the secret ladder in the order the engine made it', async ({ page }) => {
  await runFreePlay(page, 5)
  await page.getByTestId('inspector-tab-ladder').click()
  const names = await page.locator('[data-testid^="key-rung-"][data-name]').evaluateAll(els => els.map(e => e.getAttribute('data-name')))
  expect(names.length, 'rungs shown').toBeGreaterThan(8)
  const at = (n: string) => names.indexOf(n)
  expect(at('early_secret')).toBeGreaterThanOrEqual(0)
  expect(at('early_secret')).toBeLessThan(at('handshake_secret'))
  expect(at('handshake_secret')).toBeLessThan(at('master_secret'))
})

test('lesson 5 flipped record byte is caught by the AEAD tag', async ({ page }) => {
  await runFreePlay(page, 5)
  await page.getByTestId('attack-L5-flip-record-byte').click()
  await expect(page.getByTestId('attack-result')).toContainText('AEAD tag')
})
