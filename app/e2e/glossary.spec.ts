import { _electron as electron, expect, test } from '@playwright/test'
import * as os from 'node:os'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { isMethod, matches, type Glossary } from '../src/glossaryData'
import { startTour, walkTourUntil, open } from './walk'

// The glossary page. The link rule itself is tested in links.spec.ts; here a real source on the page goes through it.
const g = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'src', 'glossary.json'), 'utf8')) as Glossary
const methods = g.terms.filter(isMethod)

test('search matches the term, the short text, the kind and the uses', () => {
  const aes = methods.find(m => m.id === 'aes')!
  expect(matches(aes, '')).toBe(true)
  expect(matches(aes, 'aes')).toBe(true)
  expect(matches(aes, 'SYMMETRIC')).toBe(true)
  expect(matches(aes, 'encrypt')).toBe(true)
  expect(matches(aes, 'signature')).toBe(false)
})

test('the glossary opens from Settings with every method, its status tag, and its sources as links', async ({ page }) => {
  await open(page)
  await page.getByTestId('settings-button').click()
  await page.getByTestId('glossary-open').click()
  await expect(page.getByTestId('glossary-page')).toBeVisible()
  await expect(page.locator('[data-testid^=glossary-method-]')).toHaveCount(methods.length)
  for (const m of methods) await expect(page.getByTestId(`glossary-status-${m.id}`)).toHaveText(m.status)
  for (const m of methods.filter(m => m.statusBasis === 'draft')) await expect(page.getByTestId(`glossary-draft-${m.id}`)).toBeVisible()
  // A row opens to show its notes and its sources. Each source is a new-window link to the URL in the data.
  const des = methods.find(m => m.status === 'broken')!
  await page.getByTestId(`glossary-method-${des.id}`).click()
  const links = page.getByTestId(`glossary-detail-${des.id}`).getByTestId('glossary-source-link')
  await expect(links).toHaveCount(des.sources.length)
  for (let i = 0; i < des.sources.length; i++) {
    await expect(links.nth(i)).toHaveAttribute('href', g.sources[des.sources[i]].url)
    await expect(links.nth(i)).toHaveAttribute('target', '_blank')
    await expect(links.nth(i)).toHaveAttribute('rel', /noopener/)
  }
  // The comparison: 2 columns, and a claim with no source carries the reasoning mark.
  const reasoning = [g.comparison.symmetric, g.comparison.asymmetric].flatMap(s => [...s.strengths, ...s.weaknesses]).filter(c => c.basis === 'reasoning').length
  await expect(page.getByTestId('glossary-reasoning-mark')).toHaveCount(reasoning)
  const sym = await page.getByTestId('glossary-compare-symmetric').boundingBox()
  const asym = await page.getByTestId('glossary-compare-asymmetric').boundingBox()
  expect(Math.abs(sym!.y - asym!.y), 'the 2 columns sit side by side').toBeLessThan(2)
  expect(asym!.x).toBeGreaterThan(sym!.x + sym!.width - 1)
  // Search narrows the table and the terms, and Escape returns to the lessons.
  await page.getByTestId('glossary-search').fill('rsa')
  await expect(page.locator('[data-testid^=glossary-method-]')).toHaveCount(methods.filter(m => matches(m, 'rsa')).length)
  await page.getByTestId('glossary-search').fill('')
  await page.getByTestId('glossary-search').blur()
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('glossary-page')).toHaveCount(0)
  await expect(page.getByTestId('lesson-rail')).toBeVisible()
})

test('a term in a tour step opens its glossary entry', async ({ page }) => {
  await startTour(page, 1)
  await walkTourUntil(page, 'the GCM term', () => page.getByTestId('term-gcm').first().isVisible())
  await page.getByTestId('term-gcm').first().click()
  await expect(page.getByTestId('glossary-page')).toBeVisible()
  const entry = page.locator('#glossary-entry-gcm')
  await expect(entry).toBeInViewport()
  await page.getByTestId('glossary-back').click()
  await expect(page.getByTestId('tour-step-id')).toBeVisible()
})

// Real Electron: shell.openExternal is replaced in the main process, so the test opens no browser. A listed source goes out, an unlisted link
// goes nowhere, and the app never gets a second window or leaves its page.
test('real Electron opens a glossary source in the outside browser, refuses an unlisted link, and keeps one window', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-e2e-links-'))
  const app = await electron.launch({ args: ['.'], cwd: path.join(__dirname, '..'), env: { ...process.env, NETSEC_PORT: '5192', NETSEC_TOKEN: 'links-token', NETSEC_SECURITY_DIR: dir } })
  try {
    const win = await app.firstWindow()
    await expect(win.getByTestId('host-chip')).toContainText(/connected/i, { timeout: 60_000 })
    await app.evaluate(({ shell }) => { (globalThis as any).opened = []; shell.openExternal = async (url: string) => { (globalThis as any).opened.push(url) } })
    const page = win.url()
    await win.getByTestId('settings-button').click()
    await win.getByTestId('glossary-open').click()
    const first = methods[0]
    await win.getByTestId(`glossary-method-${first.id}`).click()
    await win.getByTestId(`glossary-detail-${first.id}`).getByTestId('glossary-source-link').first().click()
    await expect.poll(() => app.evaluate(() => (globalThis as any).opened.length)).toBe(1)
    expect(await app.evaluate(() => (globalThis as any).opened[0])).toBe(g.sources[first.sources[0]].url)
    await win.evaluate(() => { window.open('https://evil.example/', '_blank') })
    await win.evaluate(() => { const a = document.createElement('a'); a.href = 'https://evil.example/'; document.body.appendChild(a); a.click(); a.remove() })
    await win.waitForTimeout(800)
    expect(await app.evaluate(() => (globalThis as any).opened.length), 'an unlisted link went out').toBe(1)
    expect(await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().length), 'windows').toBe(1)
    expect(win.url(), 'the app left its page').toBe(page)
  } finally { await app.close() }
})

test('a term inside the wizard keeps its hover and opens no glossary page behind the dialog', async ({ page }) => {
  await open(page)
  await page.getByTestId('security-setup-button').click()
  await page.getByTestId('flow-my-login').click()
  const term = page.getByTestId('wizard-sheet').getByTestId('term-token').first()
  await expect(term).toBeVisible()
  await term.click()
  await term.press('Enter')
  await term.press(' ')
  await page.waitForTimeout(300)
  await expect(page.getByTestId('glossary-page')).toHaveCount(0)
  await expect(page.getByTestId('wizard-sheet')).toBeVisible()
  await expect(page.getByTestId('sec-page')).toBeAttached()
})

test('Space on a term in a tour opens its entry, as Enter does', async ({ page }) => {
  await startTour(page, 1)
  await walkTourUntil(page, 'the GCM term', () => page.getByTestId('term-gcm').first().isVisible())
  await page.getByTestId('term-gcm').first().focus()
  await page.keyboard.press(' ')
  await expect(page.getByTestId('glossary-page')).toBeVisible()
})
