import { expect, test, type Page } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { MIN_RATIO, scanPage, setTheme } from './contrast'
import { open, PORT, TOKEN } from './walk'

// V3: the Show keys switch is real. The Host redacts at its boundary, so this spec drives the switch and reads the screen against the Host's own answers.
const OUT = path.join(__dirname, '..', 'test-results', 'show-keys-v3')
const shot = async (page: Page, name: string) => { fs.mkdirSync(OUT, { recursive: true }); await page.screenshot({ path: path.join(OUT, `${name}.png`) }) }
const api = (method: string, p: string, body?: unknown) =>
  fetch(`http://127.0.0.1:${PORT}${p}`, { method, headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
const hostOn = async () => ((await (await api('GET', '/api/security/show-keys')).json()) as { on: boolean }).on

test.describe.configure({ mode: 'serial' })
test.beforeEach(async () => { await api('PUT', '/api/security/show-keys', { on: true }) })
test.afterAll(async () => { await api('PUT', '/api/security/show-keys', { on: true }) })

async function freePlay(page: Page, lesson: number) {
  await open(page)
  await page.getByTestId(`lesson-item-${lesson}`).click()
  await page.getByTestId('mode-free').click()
  await page.getByTestId('free-start').click()
  await page.getByTestId('free-run').click()
  await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 60_000 })
}
const rowText = async (page: Page) => (await page.locator('[data-testid^="secret-row-"]').allInnerTexts()).join('\n')

async function contrast(page: Page, theme: string, screen: string) {
  await page.evaluate(() => Promise.all(document.getAnimations().filter(a => a.effect?.getComputedTiming().iterations !== Infinity).map(a => a.finished.catch(() => null))))
  await page.waitForTimeout(300)
  const s = await scanPage(page)
  console.log(`${theme} ${screen}: ${s.checked} texts checked, ${s.fails.length} failed`)
  expect(s.fails.map(f => `${screen}: ${f.where} "${f.text}" ${f.ratio} (${f.fg} on ${f.bg})`), `${theme} ${screen}`).toEqual([])
}

test('ON: rows show bytes, the Keys in use strip names the key, and the switch reads ON', async ({ page }) => {
  await freePlay(page, 1)
  await expect(page.getByTestId('show-keys-switch')).toBeChecked()
  expect(await rowText(page)).toMatch(/[0-9a-f]{16,}/i)
  await expect(page.getByTestId('keys-in-use')).toBeVisible()
  await expect(page.locator('[data-testid^="key-in-use-"]:not([data-testid^="key-in-use-value-"])').first()).toBeVisible()
  await expect(page.getByTestId('show-keys-off-banner')).toHaveCount(0)
  await shot(page, '01-on')
})

test('OFF: bytes leave the panel at once, fingerprints stay, the banner shows, and ON brings the bytes back', async ({ page }) => {
  await freePlay(page, 1)
  await page.getByTestId('show-keys-switch').uncheck()
  await expect.poll(hostOn).toBe(false)
  await expect.poll(async () => /[0-9a-f]{32,}/i.test(await rowText(page))).toBe(false)
  expect(await rowText(page)).toMatch(/fp:[0-9a-f]{16}/)
  await expect(page.getByTestId('show-keys-off-banner')).toContainText('Show keys is off, so you see a short fingerprint of each key.')
  await expect(page.getByTestId('keys-in-use')).toContainText(/fp:[0-9a-f]{16}/)
  await expect(page.locator('[data-testid^="secret-reveal-"]')).toHaveCount(0)
  await shot(page, '02-off')
  await page.getByTestId('show-keys-switch').check()
  await expect.poll(hostOn).toBe(true)
  await expect.poll(async () => /[0-9a-f]{16,}/i.test(await rowText(page))).toBe(true)
  await expect(page.getByTestId('show-keys-off-banner')).toHaveCount(0)
})

test('OFF: two sides that hold one key still show a match, from the fingerprints', async ({ page }) => {
  await freePlay(page, 3)
  await page.getByTestId('show-keys-switch').uncheck()
  await expect.poll(hostOn).toBe(false)
  await expect.poll(async () => /[0-9a-f]{32,}/i.test(await rowText(page))).toBe(false)
  await expect(page.getByTestId('convergence-match').first()).toBeVisible()
  await shot(page, '03-lesson3-off')
})

test('OFF: the key log is refused by name', async ({ page }) => {
  await freePlay(page, 1)
  const id = await page.locator('.statusbar').innerText().then(t => /session (?<id>\S+)/.exec(t)?.groups?.id ?? '')
  expect(id).not.toBe('')
  await page.getByTestId('show-keys-switch').uncheck()
  await expect.poll(hostOn).toBe(false)
  const r = await api('GET', `/api/sessions/${id}/keylog`)
  expect(r.status).toBe(409)
  expect(((await r.json()) as { code: string }).code).toBe('KEYS_HIDDEN')
})

for (const theme of ['light', 'dark'] as const) {
  test(`every Show keys state reads at ${MIN_RATIO} to 1 in the ${theme} theme`, async ({ page }) => {
    test.setTimeout(240_000)
    await freePlay(page, 1)
    await setTheme(page, theme)
    await contrast(page, theme, 'lesson 1, keys shown, strip')
    await page.getByTestId('show-keys-switch').uncheck()
    await expect.poll(hostOn).toBe(false)
    await expect(page.getByTestId('show-keys-off-banner')).toBeVisible()
    await contrast(page, theme, 'lesson 1, keys hidden, banner, strip')
    for (const n of [3, 6]) {
      await page.getByTestId(`lesson-item-${n}`).click()
      await page.getByTestId('free-start').click()
      await page.getByTestId('free-run').click()
      await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 60_000 })
      await contrast(page, theme, `lesson ${n}, keys hidden`)
      for (const tab of await page.locator('[data-testid^=inspector-tab-]').all()) { await tab.click(); await contrast(page, theme, `lesson ${n}, keys hidden, tab ${await tab.getAttribute('data-testid')}`) }
    }
    await shot(page, `04-off-${theme}`)
  })
}
