import { expect, test } from '@playwright/test'
import * as path from 'node:path'
import { runFreePlay, tourIds, walkTour } from './walk'

test('walks every step of lesson 4 against the live Host', async ({ page }) => {
  const visited = await walkTour(page, 4, path.join(__dirname, '..', 'test-results', 'lesson-4'))
  expect(visited).toEqual(tourIds(4))
})

test('lesson 4 draws root, leaf and proof as linked cards, and the links pass on a clean run', async ({ page }) => {
  await runFreePlay(page, 4)
  await page.getByTestId('inspector-tab-chain').click()
  await expect(page.getByTestId('chain-card-root')).toBeVisible()
  await expect(page.getByTestId('chain-card-leaf')).toBeVisible()
  await expect(page.getByTestId('chain-card-proof')).toBeVisible()
  await expect(page.getByTestId('chain-link-1')).toHaveAttribute('data-status', 'pass')
  await expect(page.getByTestId('chain-link-2')).toHaveAttribute('data-status', 'pass')
})

test('lesson 4 expired certificate breaks the validity badge and names the check', async ({ page }) => {
  await runFreePlay(page, 4)
  await page.getByTestId('attack-L4-expired-cert').click()
  await expect(page.getByTestId('attack-result')).toContainText('validity window')
  await page.getByTestId('inspector-tab-chain').click()
  await expect(page.getByTestId('chain-badge-validity window')).toContainText('✕')
})
