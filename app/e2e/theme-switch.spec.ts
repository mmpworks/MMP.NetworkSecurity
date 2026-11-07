import { expect, test } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { setTheme } from './contrast'
import { open } from './walk'

// The theme switch: System, Light, Dark. A first run opens in Dark. The choice survives a reload, and System follows the operating system live.
const OUT = path.join(__dirname, '..', 'test-results', 'theme')
const themeOf = (page: import('@playwright/test').Page) => page.evaluate(() => document.documentElement.dataset.theme)

test('the switch offers System, Light, Dark in that order, and a first run opens in Dark', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'light' })
  await open(page)
  const sel = page.getByTestId('theme-select')
  await expect(sel).toHaveValue('dark')
  expect(await themeOf(page)).toBe('dark')
  await expect(sel.locator('option')).toHaveText(['System', 'Light', 'Dark'])
})

test('System follows the operating system while the page stays open', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' })
  await open(page)
  await setTheme(page, 'system')
  expect(await themeOf(page)).toBe('dark')
  await page.emulateMedia({ colorScheme: 'light' })
  await expect.poll(() => themeOf(page)).toBe('light')
  await page.emulateMedia({ colorScheme: 'dark' })
  await expect.poll(() => themeOf(page)).toBe('dark')
})

test('Light and Dark ignore the operating system, and the choice survives a reload', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' })
  await open(page)
  await setTheme(page, 'light')
  expect(await themeOf(page)).toBe('light')
  await expect(page.locator('.v-theme--nsLight').first()).toBeVisible()
  await page.reload()
  await expect(page.getByTestId('host-chip')).toContainText(/connected/i)
  await expect(page.getByTestId('theme-select')).toHaveValue('light')
  expect(await themeOf(page)).toBe('light')
  await page.emulateMedia({ colorScheme: 'light' })
  await setTheme(page, 'dark')
  await page.reload()
  await expect(page.getByTestId('host-chip')).toContainText(/connected/i)
  await expect(page.getByTestId('theme-select')).toHaveValue('dark')
  expect(await themeOf(page)).toBe('dark')
  await setTheme(page, 'system')
  await page.reload()
  await expect(page.getByTestId('theme-select')).toHaveValue('system')
})

test('an unknown saved value falls back to Dark', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('mmpns.theme', 'purple'))
  await open(page)
  await expect(page.getByTestId('theme-select')).toHaveValue('dark')
})

for (const theme of ['light', 'dark'] as const) {
  test(`the Security setup screen and a tour step in the ${theme} theme`, async ({ page }) => {
    fs.mkdirSync(OUT, { recursive: true })
    await open(page)
    await setTheme(page, theme)
    await page.getByTestId('security-setup-button').click()
    await expect(page.getByTestId('sec-page')).toBeVisible()
    await page.waitForTimeout(500)
    await page.screenshot({ path: path.join(OUT, `${theme}-security-setup.png`) })
    await page.getByTestId('sec-back').click()
    await page.getByTestId('lesson-item-1').click()
    await page.getByRole('button', { name: /start tour/i }).click()
    await expect(page.getByTestId('tour-step-id')).toBeVisible()
    await page.waitForTimeout(500)
    await page.screenshot({ path: path.join(OUT, `${theme}-tour-step.png`) })
  })
}
