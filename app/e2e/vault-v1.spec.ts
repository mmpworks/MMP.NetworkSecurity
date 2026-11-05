import { expect, test, type Page } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { MIN_RATIO, scanPage, setTheme } from './contrast'
import { open } from './walk'

// V1 vault page and the three exercise screens, on a real Host with the /api/security/vault routes. Contrast is tested on every screen in both themes.
const OUT = path.join(__dirname, '..', 'test-results', 'vault-v1')
const shot = async (page: Page, name: string) => { fs.mkdirSync(OUT, { recursive: true }); await page.screenshot({ path: path.join(OUT, `${name}.png`) }) }
const TEST_KEYS = 'Use test keys only. This course shows your keys on screen and in saved files.'

async function openVault(page: Page) {
  await open(page)
  await page.getByTestId('security-setup-button').click()
  await page.getByTestId('sec-vault-exercise').click()
  await expect(page.getByTestId('vault-exercise')).toBeVisible()
}

async function contrast(page: Page, theme: string, screen: string) {
  await page.evaluate(() => Promise.all(document.getAnimations().filter(a => a.effect?.getComputedTiming().iterations !== Infinity).map(a => a.finished.catch(() => null))))
  await page.waitForTimeout(300)
  const s = await scanPage(page)
  console.log(`${theme} ${screen}: ${s.checked} texts checked, ${s.fails.length} failed`)
  expect(s.fails.map(f => `${screen}: ${f.where} "${f.text}" ${f.ratio} (${f.fg} on ${f.bg})`), `${theme} ${screen}, ${s.checked} texts checked`).toEqual([])
}

test('the vault page opens from the map footer, states what it is, and lists the two exercise keys without key bytes', async ({ page }) => {
  await openVault(page)
  await expect(page.getByTestId('vault-statement')).toHaveText('Practice vault. Not an HSM. Not FIPS validated. Non-export is a rule in our code. Anyone can open the SQLite file and read the wrapped key.')
  for (const k of ['exercise/signing', 'exercise/derive']) {
    await expect(page.getByTestId(`vault-key-${k}`)).toBeVisible()
    await expect(page.getByTestId(`vault-key-hidden-${k}`)).toHaveText('The course refuses to show it. A real HSM would refuse too. These files could still open it here.')
    await expect(page.getByTestId(`vault-key-fingerprint-${k}`)).not.toHaveText('')
  }
  await shot(page, '01-vault-page')
  await page.getByTestId('vault-back').click()
  await expect(page.getByTestId('sec-page')).toBeVisible()
})

test('screen 1: the test-keys line comes first, a message is signed and checked by OpenSSL, and one label gives one fingerprint', async ({ page }) => {
  await openVault(page)
  const screen = page.getByTestId('vault-sign-derive')
  await expect(screen.locator('p').first()).toHaveText(TEST_KEYS)
  await page.getByTestId('vault-sign-message').fill('pay the bill')
  await page.getByTestId('vault-sign-run').click()
  await expect(page.getByTestId('vault-sign-signature')).not.toHaveText('')
  await expect(page.getByTestId('vault-sign-public')).not.toHaveText('')
  await page.getByTestId('vault-sign-check').click()
  await expect(page.getByTestId('prove-command')).toContainText('openssl')
  await expect(page.getByTestId('prove-output')).not.toHaveText('')
  await shot(page, '02-sign')
  await expect(page.getByTestId('vault-derive-note')).toHaveText('A typed label stands in for a key serial number. This is the idea behind DUKPT. It is not DUKPT.')
  await page.getByTestId('vault-derive-label').fill('pump-reader-4')
  await page.getByTestId('vault-derive-run').click()
  await expect(page.getByTestId('vault-derived-0')).toBeVisible()
  await page.getByTestId('vault-derive-run').click()
  await expect(page.getByTestId('vault-derived-1')).toBeVisible()
  const fp0 = await page.getByTestId('vault-derived-fingerprint-0').textContent()
  const fp1 = await page.getByTestId('vault-derived-fingerprint-1').textContent()
  expect(fp0).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/)
  expect(fp1).toBe(fp0)
  await expect(page.getByTestId('vault-derive-compare')).toHaveText('Same label, same fingerprint.')
  await page.getByTestId('vault-derive-label').fill('another-reader')
  await page.getByTestId('vault-derive-run').click()
  expect(await page.getByTestId('vault-derived-fingerprint-2').textContent()).not.toBe(fp0)
  await expect(page.getByTestId('vault-derive-compare')).toHaveText('Another label gives another key.')
  await shot(page, '03-derive')
})

test('screen 2: reading a non-exportable key out is refused with VAULT_EXPORT_REFUSED', async ({ page }) => {
  await openVault(page)
  await page.getByTestId('vault-tab-refuse').click()
  await page.getByTestId('vault-refuse-run').click()
  await expect(page.getByTestId('vault-refuse-code')).toHaveText('VAULT_EXPORT_REFUSED')
  await expect(page.getByTestId('vault-refuse-result')).toContainText('The vault refused. This key cannot be read out.')
  await shot(page, '04-refuse')
})

test('screen 3: the audit list shows the rows of this session, and the chain check says every row fits', async ({ page }) => {
  await openVault(page)
  await page.getByTestId('vault-tab-audit').click()
  await page.getByTestId('vault-audit-run').click()
  await expect(page.locator('[data-testid^="vault-audit-row-"]').first()).toBeVisible()
  await expect(page.getByTestId('vault-audit-note')).toBeVisible()
  await page.getByTestId('vault-audit-check').click()
  await expect(page.getByTestId('vault-audit-chain')).toContainText('Every row fits the row before it.')
  await shot(page, '05-audit')
})

for (const theme of ['light', 'dark'] as const) {
  test(`every vault screen and result reads at ${MIN_RATIO} to 1 in the ${theme} theme`, async ({ page }) => {
    await open(page)
    await setTheme(page, theme)
    await page.getByTestId('security-setup-button').click()
    await contrast(page, theme, 'security setup with the vault button')
    await page.getByTestId('sec-vault-exercise').click()
    await contrast(page, theme, 'vault page, sign and derive')
    await page.getByTestId('vault-sign-run').click()
    await page.getByTestId('vault-sign-check').click()
    await page.getByTestId('vault-derive-run').click()
    await page.getByTestId('vault-derive-run').click()
    await expect(page.getByTestId('vault-derived-1')).toBeVisible()
    await contrast(page, theme, 'sign result, check output and derived keys')
    await page.getByTestId('vault-tab-refuse').click()
    await contrast(page, theme, 'refuse screen')
    await page.getByTestId('vault-refuse-run').click()
    await expect(page.getByTestId('vault-refuse-result')).toBeVisible()
    await contrast(page, theme, 'refusal result')
    await page.getByTestId('vault-tab-audit').click()
    await page.getByTestId('vault-audit-run').click()
    await page.getByTestId('vault-audit-check').click()
    await expect(page.getByTestId('vault-audit-chain')).toBeVisible()
    await contrast(page, theme, 'audit rows and chain result')
    await page.waitForTimeout(200)
    await shot(page, `06-audit-${theme}`)
  })
}
