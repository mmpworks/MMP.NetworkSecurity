import { expect, test } from '@playwright/test'
import * as path from 'node:path'
import { runFreePlay, tourIds, walkTour } from './walk'

test('walks every step of lesson 7 against the live Host', async ({ page }) => {
  const visited = await walkTour(page, 7, path.join(__dirname, '..', 'test-results', 'lesson-7'))
  expect(visited).toEqual(tourIds(7))
})

test('lesson 7 races TLS 1.1 against TLS 1.3 with counters read from the trace', async ({ page }) => {
  await runFreePlay(page, 7)
  await expect(page.getByTestId('race-left')).toBeVisible()
  await expect(page.getByTestId('race-right')).toBeVisible()
  const n = async (id: string) => Number((await page.getByTestId(id).textContent()) ?? '')
  const old = await n('race-count-messages-left')
  const modern = await n('race-count-messages-right')
  expect(old, 'TLS 1.1 messages').toBeGreaterThan(0)
  expect(modern, 'TLS 1.3 messages').toBeGreaterThan(0)
  expect(await n('race-count-roundtrips-left'), 'TLS 1.1 round trips before data').toBe(2)
  expect(await n('race-count-roundtrips-right'), 'TLS 1.3 round trips before data').toBe(1)
})

test('lesson 7 flipped record is caught by the record HMAC', async ({ page }) => {
  await runFreePlay(page, 7)
  await page.getByTestId('attack-L7-flip-record').click()
  await expect(page.getByTestId('attack-result')).toContainText('record HMAC')
})
