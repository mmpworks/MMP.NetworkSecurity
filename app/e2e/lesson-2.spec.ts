import { expect, test } from '@playwright/test'
import * as path from 'node:path'
import { runFreePlay, tourIds, walkTour } from './walk'

test('walks every step of lesson 2 against the live Host', async ({ page }) => {
  const visited = await walkTour(page, 2, path.join(__dirname, '..', 'test-results', 'lesson-2'))
  expect(visited).toEqual(tourIds(2))
})

test('lesson 2 draws the avalanche as 256 bit cells, and the count matches the cells', async ({ page }) => {
  await runFreePlay(page, 2)
  await page.getByTestId('inspector-tab-measures').click()
  await expect(page.getByTestId('avalanche-grid')).toBeVisible()
  await expect(page.locator('[data-testid=avalanche-grid] .abit')).toHaveCount(256)
  const on = await page.locator('[data-testid=avalanche-grid] .abit.on').count()
  const text = (await page.getByTestId('avalanche-count').textContent()) ?? ''
  expect(Number(text.match(/(\d+) of 256/)?.[1]), 'count in the text equals the cells drawn').toBe(on)
  expect(on, 'one flipped bit changes about half the output bits').toBeGreaterThan(80)
  expect(on).toBeLessThan(176)
})

test('lesson 2 attack on HMAC names HMAC compare', async ({ page }) => {
  await runFreePlay(page, 2)
  await page.getByTestId('attack-L2-flip-hmac-tag').click()
  await expect(page.getByTestId('attack-result')).toContainText('HMAC compare')
})
