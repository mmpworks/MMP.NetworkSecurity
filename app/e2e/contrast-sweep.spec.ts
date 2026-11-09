import { expect, test, type Page } from '@playwright/test'
import { MIN_RATIO, scanPage, setTheme, settle, type ScanFail } from './contrast'
import { startOwnHost, type OwnHost } from './own-host'
import { open, walkTourUntil } from './walk'

// The class behind the unreadable tooltip: text that fails 4.5 to 1 on its own box. This visits every screen, tooltip, dialog, banner and chip
// in both themes and tests every visible piece of text. Each visit prints "checked N, failed M". The test fails on any failure.
const api = (method: string, p: string, body?: unknown) =>
  fetch(`http://127.0.0.1:${host.port}${p}`, { method, headers: { Authorization: `Bearer ${host.token}`, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })

// The sign-in flow below makes a key for good, and each theme walks that flow from the start, so each theme gets its own Host.
let host: OwnHost
test.beforeEach(async () => { host = await startOwnHost() })
test.afterEach(async () => { await host.stop() })

const all: Record<string, ScanFail[]> = {}
const log: string[] = []

async function visit(page: Page, theme: string, screen: string) {
  await settle(page)
  const s = await scanPage(page)
  log.push(`${theme.padEnd(5)} ${screen.padEnd(44)} checked ${String(s.checked).padStart(4)}, failed ${s.fails.length}`)
  for (const f of s.fails) (all[`${theme}`] ??= []).push({ ...f, where: `${screen}: ${f.where}` })
}

async function hoverVisit(page: Page, theme: string, testId: string) {
  await page.getByTestId(testId).first().hover()
  await page.waitForTimeout(500)
  await visit(page, theme, `tooltip of ${testId}`)
  await page.mouse.move(0, 400)
  await page.waitForTimeout(250)
}

for (const theme of ['dark', 'light'] as const) {
  test(`every screen, tooltip, dialog, banner and chip reads at ${MIN_RATIO} to 1 in the ${theme} theme`, async ({ page }) => {
    // Measured per theme in full suites on 2026-11-08: 4.2 to 4.8 minutes on a quiet machine, 7.0 to 8.3 under load. 8 minutes was too
    // close, and one rerun timed out while closing the page (#323).
    test.setTimeout(720_000)
    await api('PUT', '/api/security/types/token.issuer/mode', { mode: 'BuiltIn' })
    await api('PUT', '/api/security/types/device.enrolment/mode', { mode: 'BuiltIn' })
    await open(page, host)
    await setTheme(page, theme)
    await visit(page, theme, 'start, nothing picked')
    for (const id of ['training-only-label', 'keys-chip', 'show-keys-switch']) await hoverVisit(page, theme, id)
    await page.getByTestId('settings-button').click()
    await visit(page, theme, 'settings menu')
    await page.getByRole('button', { name: 'Keyboard shortcuts' }).click()
    await visit(page, theme, 'keyboard shortcuts dialog')
    await page.keyboard.press('Escape')

    // The glossary page, with one method row open.
    await page.getByTestId('settings-button').click()
    await page.getByTestId('glossary-open').click()
    await page.locator('[data-testid^=glossary-method-]').first().click()
    await visit(page, theme, 'glossary')
    await page.getByTestId('glossary-back').click()

    // A tour step with glossary terms, and the term tooltip.
    await page.getByTestId('lesson-item-1').click()
    await page.getByRole('button', { name: /start tour/i }).click()
    await expect(page.getByTestId('tour-step-id')).toBeVisible()
    await visit(page, theme, 'lesson 1 tour step 1')
    await walkTourUntil(page, 'the GCM term', () => page.getByTestId('term-gcm').first().isVisible())
    await visit(page, theme, 'lesson 1 tour step with the GCM term')
    await hoverVisit(page, theme, 'term-gcm')

    // Free play on every lesson, with every inspector tab and the attack result.
    for (let n = 0; n <= 11; n++) {
      await page.getByTestId(`lesson-item-${n}`).click()
      await page.getByTestId('mode-free').click()
      await page.getByTestId('free-start').click()
      await page.getByTestId('free-run').click()
      await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 60_000 })
      await page.getByTestId('view-both').click()
      await visit(page, theme, `lesson ${n} free play, both views`)
      for (const tab of await page.locator('[data-testid^=inspector-tab-]').all()) {
        await tab.click()
        await visit(page, theme, `lesson ${n} inspector tab ${(await tab.getAttribute('data-testid'))?.replace('inspector-tab-', '')}`)
      }
      const attack = page.locator('[data-testid^=attack-L]').first()
      if (await attack.count()) { await attack.click(); await expect(page.getByTestId('attack-result')).toBeVisible(); await visit(page, theme, `lesson ${n} attack result`) }
      await page.getByTestId('view-endpoints').click()
      await page.getByTestId('mode-tour').click()
    }

    // Security setup, every wizard screen, the cancel sheet, the refusal banner and the file refusal.
    await api('PUT', '/api/security/types/token.issuer/mode', { mode: 'Mine' })
    await page.reload()
    await expect(page.getByTestId('host-chip')).toContainText(/connected/i)
    await page.getByTestId('lesson-item-10').click()
    await page.getByRole('button', { name: /start tour/i }).click()
    await expect(page.getByTestId('security-needs-banner')).toBeVisible()
    await visit(page, theme, 'refusal banner')
    await page.getByTestId('needs-use-builtin').click()
    await visit(page, theme, 'refusal banner, confirm')
    await page.getByTestId('needs-confirm-no').click()
    await page.getByTestId('security-needs-banner').getByRole('button', { name: 'Close' }).click().catch(() => {})
    await api('PUT', '/api/security/types/token.issuer/mode', { mode: 'BuiltIn' })
    await page.getByTestId('security-setup-button').click()
    await visit(page, theme, 'security setup, all built-in')
    await hoverVisit(page, theme, 'sec-show-keys-switch')
    await page.getByTestId('flow-my-login').click()
    await visit(page, theme, 'wizard intro')
    await page.getByTestId('wizard-next').click()
    await visit(page, theme, 'wizard make')
    await page.getByTestId('flow-files-link').click()
    await page.getByTestId('flow-file-path-token.issuer').fill('C:/no/such/file.pem')
    await page.getByTestId('flow-files-send').click()
    await expect(page.getByTestId('wizard-error')).toBeVisible()
    await visit(page, theme, 'wizard files, refusal')
    await page.getByTestId('wizard-cancel').click()
    await visit(page, theme, 'wizard cancel sheet')
    await page.getByTestId('wizard-cancel-back').click()
    await page.getByTestId('wizard-back').click()
    await page.getByTestId('flow-make-button').click()
    await visit(page, theme, 'wizard review')
    await page.getByTestId('wizard-next').click()
    await page.getByTestId('flow-check-button').click()
    await expect(page.getByTestId('check-says-token.issuer')).toBeVisible()
    await visit(page, theme, 'wizard check')
    await page.getByTestId('wizard-next').click()
    await visit(page, theme, 'wizard done')
    await page.getByTestId('flow-done-map').click()
    await visit(page, theme, 'security setup, keys set up')
    await api('PUT', '/api/security/types/pki.root-ca/mode', { mode: 'Mine' })
    await page.reload()
    await page.getByTestId('security-setup-button').click()
    await visit(page, theme, 'security setup, one key needs setup')

    console.log(log.filter(l => l.startsWith(theme)).join('\n'))
    const fails = all[theme] ?? []
    const uniq = [...new Map(fails.map(f => [`${f.where.split(': ')[1].replace(/-(?<n>\d+)\]/, '-N]')}|${f.fg}|${f.bg}`, f])).values()]
    expect(uniq.map(f => `${f.where} "${f.text}" ${f.ratio} (${f.fg} on ${f.bg})`), `elements under ${MIN_RATIO} to 1 in the ${theme} theme`).toEqual([])
    await api('PUT', '/api/security/types/pki.root-ca/mode', { mode: 'BuiltIn' })
  })
}
