import { expect, test } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'

// The suite under acceptance/ walks lessons 1 to 11. Lesson 0 is the toy, so this spec is its only end to end proof.
// It runs against a real Host and the tour file app/src/tours/lesson-00.json.
const PORT = 5190
const TOKEN = 'lesson0-token'
const OUT = path.join(__dirname, '..', 'test-results', 'lesson-0')

function tourIds(): string[] {
  const j = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'src', 'tours', 'lesson-00.json'), 'utf8'))
  return (Array.isArray(j) ? j : j.steps).map((s: { id: string }) => s.id)
}

async function open(page: import('@playwright/test').Page) {
  await page.addInitScript(({ port, token }) => { (window as any).netsec = { host: { port, token } } }, { port: PORT, token: TOKEN })
  await page.goto(`/?port=${PORT}&token=${TOKEN}`)
  await expect(page.getByTestId('host-chip')).toContainText(/connected/i)
}

test('the rail shows lesson 0 as Start here beside lessons 1 to 11', async ({ page }) => {
  await open(page)
  await expect(page.getByTestId('lesson-item-0')).toContainText('Start here')
  for (let n = 1; n <= 11; n++) await expect(page.getByTestId(`lesson-item-${n}`)).toBeVisible()
})

test('the target device dropdown offers this computer and shows the CE boxes disabled', async ({ page }) => {
  await open(page)
  const target = page.getByTestId('target-select')
  await expect(target).toHaveValue('this-computer')
  const options = target.locator('option')
  await expect(options).toHaveText(['This computer', 'WinCE 6', 'WinCE 7'])
  await expect(options.nth(0)).toHaveJSProperty('disabled', false)
  await expect(options.nth(1)).toHaveJSProperty('disabled', true)
  await expect(options.nth(2)).toHaveJSProperty('disabled', true)
  fs.mkdirSync(OUT, { recursive: true })
  await page.screenshot({ path: path.join(OUT, 'target-select.png'), clip: { x: 0, y: 0, width: 1000, height: 60 } })
})

test('walks every step of lesson 0 against the live Host', async ({ page }) => {
  const ids = tourIds()
  expect(ids.length).toBeGreaterThan(0)
  fs.mkdirSync(OUT, { recursive: true })
  await open(page)
  await page.getByTestId('lesson-item-0').click()
  await page.getByRole('button', { name: /start tour/i }).click()
  await expect(page.getByTestId('training-only-label')).toContainText('TRAINING ONLY')
  const visited: string[] = []
  for (let i = 0; i < ids.length; i++) {
    await expect(page.getByTestId('tour-step-id')).toHaveText(ids[i])
    visited.push(ids[i])
    await expect(page.getByTestId('error-banner')).toHaveCount(0)
    await page.screenshot({ path: path.join(OUT, `${ids[i]}.png`) })
    const next = page.getByTestId('tour-next')
    if (await next.isDisabled()) {
      const tryIt = page.getByTestId('tour-try-it-action')
      if (await tryIt.isVisible()) await tryIt.click()
    }
    await expect(next).toBeEnabled()
    if (i < ids.length - 1) await next.click()
  }
  expect(visited).toEqual(ids)
})

test('the eavesdropper view hides what the wire hides, and the attack names its check', async ({ page }) => {
  await open(page)
  await page.getByTestId('lesson-item-0').click()
  await page.getByTestId('mode-free').click()
  await page.getByTestId('free-start').click()
  await page.getByTestId('free-run').click()
  await expect(page.locator('[data-testid^=diagram-message-]').first()).toBeVisible()
  await page.getByTestId('view-eavesdropper').click()
  await expect(page.getByTestId('eve-count')).toContainText(/read \d+ of \d+ messages/)
  await page.getByTestId('view-endpoints').click()
  await page.getByTestId('attack-L0-flip-wire-byte').click()
  await expect(page.getByTestId('attack-result')).toContainText('echo compare')
  await expect(page.getByTestId('check-fail-badge').first()).toBeVisible()
})

test('the OS transport relabels the chip and hides secret rows', async ({ page }) => {
  await open(page)
  await page.getByTestId('transport-switch').click()
  await expect(page.getByTestId('training-only-label')).toContainText('OS TRANSPORT')
  expect(await page.locator('[data-testid^="secret-row-"]').count()).toBe(0)
})
