import { expect, test, type Page, type Route } from '@playwright/test'
import { runFreePlay } from './walk'

// How the AES walk fetches its two replies (docs/walkthrough-design.md sections 2.2b and 2.3; Jared and Richard on #241).
// The walk needs the block and the public tables, because Nk comes from the tables' size table.
const TABLES = '**/api/walk/aes/tables'

/** Leaves Show keys on, because the Host keeps the toggle for every later spec. */
async function keysOn(page: Page) {
  const sw = page.getByTestId('show-keys-switch')
  if (!(await sw.isChecked())) await sw.click()
  await expect(sw).toBeChecked()
}

test('a failed tables call names the tables route in the walk\'s error line', async ({ page }) => {
  await runFreePlay(page, 1)
  await page.route(TABLES, r => r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'TEST_TABLES_DOWN' }) }))
  await page.getByTestId('aes-walk-tab').click()
  await expect(page.getByTestId('aes-walk-error')).toContainText('the tables route failed: TEST_TABLES_DOWN')
})

test('callers that race before the first tables reply share one request', async ({ page }) => {
  await runFreePlay(page, 1)
  let asks = 0
  let release!: () => void
  const held = new Promise<void>(r => { release = r })
  await page.route(TABLES, async (r: Route) => { asks++; await held; await r.continue() })
  try {
    // Caller 1: the walk opens and asks for the block and the tables.
    await page.getByTestId('aes-walk-tab').click()
    // Callers 2 and 3: the closed walk asks for the tables to show the S-box, and the flip back on asks again for the walk.
    await page.getByTestId('show-keys-switch').click()
    await expect(page.getByTestId('aes-walk-closed')).toBeVisible()
    await page.getByTestId('show-keys-switch').click()
    await expect(page.getByTestId('show-keys-switch')).toBeChecked()
    release()
    await expect(page.getByTestId('aes-walk-step-kind'), 'the walk opens once the tables arrive').toBeVisible({ timeout: 30_000 })
    expect(asks, 'one tables request for all callers').toBe(1)
  } finally {
    release()
    await keysOn(page)
  }
})
