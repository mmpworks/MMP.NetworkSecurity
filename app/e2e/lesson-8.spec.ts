import { expect, test } from '@playwright/test'
import * as path from 'node:path'
import { runFreePlay, tourIds, walkTour } from './walk'

test('walks every step of lesson 8 against the live Host', async ({ page }) => {
  const visited = await walkTour(page, 8, path.join(__dirname, '..', 'test-results', 'lesson-8'))
  expect(visited).toEqual(tourIds(8))
})

test('lesson 8 shows the host key card, and a divider where the legacy round starts', async ({ page }) => {
  await runFreePlay(page, 8)
  await page.getByTestId('inspector-tab-hostkey').click()
  await expect(page.getByTestId('hostkey-fingerprint').first()).toContainText(/^SHA256:/)
  await expect(page.getByTestId('hostkey-status').first()).toHaveAttribute('data-status', 'pass')
  await expect(page.getByTestId('round-divider').first()).toContainText('ssh-legacy')
})

test('lesson 8 changed host key is refused by known_hosts match, and the card says so', async ({ page }) => {
  await runFreePlay(page, 8)
  await page.getByTestId('attack-L8-change-host-key').click()
  await expect(page.getByTestId('attack-result')).toContainText('known_hosts match')
  await page.getByTestId('inspector-tab-hostkey').click()
  await expect(page.getByTestId('hostkey-status').first()).toHaveAttribute('data-status', 'fail')
})
