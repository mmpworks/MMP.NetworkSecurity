import { expect, test, type Page } from '@playwright/test'
import { open, runFreePlay } from './walk'

// The section shell (docs/sections-plan.md, slice P1). Kill condition lines 1 and 2: 3 of 3 sections are live, and 12 of 12 lessons are in Lessons with their numbers kept.
const SECTIONS = ['handshake', 'techniques', 'lessons'] as const
const TECHNIQUES = ['AES', 'HMAC and chain', 'Feistel', 'Diffie-Hellman', 'X25519', 'Ed25519', 'ECDSA P-256']
const HANDSHAKE = ['The wire and the eavesdropper', 'TLS 1.3 messages and key schedule', 'The certificate chain']

const barRows = (page: Page) => page.getByTestId('top-bar').evaluate(bar => {
  const mids = [...bar.children].filter(e => e.getBoundingClientRect().height > 0).map(e => { const b = e.getBoundingClientRect(); return Math.round(b.top + b.height / 2) })
  return Math.max(...mids) - Math.min(...mids) <= 4 ? 1 : 2
})

test('the top bar holds 3 sections in order, and the app opens in Lessons', async ({ page }) => {
  await open(page)
  const sw = page.getByTestId('section-switch')
  await expect(sw.locator('button')).toHaveText(['Handshake', 'Techniques', 'Lessons'])
  await expect(page.getByTestId('section-lessons')).toHaveAttribute('aria-pressed', 'true')
  await expect(page.getByTestId('lesson-rail')).toBeVisible()
})

test('Lessons holds 12 of 12 lessons with their numbers kept', async ({ page }) => {
  await open(page)
  for (let n = 0; n <= 11; n++) {
    const item = page.getByTestId(`lesson-item-${n}`)
    await expect(item).toBeVisible()
    await expect(item.locator('.rail-num')).toHaveText(String(n))
  }
})

test('Techniques lists its 7 items and Handshake its 3 walks, as placeholders, and Lessons comes back as it was', async ({ page }) => {
  await runFreePlay(page, 1)
  await page.getByTestId('section-techniques').click()
  await expect(page.getByTestId('lesson-rail')).toBeHidden()
  await expect(page.getByTestId('section-rail').locator('[data-testid^=walk-item-] .rail-title')).toHaveText(TECHNIQUES)
  await expect(page.getByTestId('section-rail')).not.toContainText('slice')
  await page.getByTestId('walk-item-hmac').click()
  await expect(page.getByTestId('section-placeholder')).toContainText('HMAC and chain')
  await page.getByTestId('section-handshake').click()
  await expect(page.getByTestId('section-rail').locator('[data-testid^=walk-item-] .rail-title')).toHaveText(HANDSHAKE)
  await expect(page.getByTestId('section-placeholder')).toBeVisible()
  await page.getByTestId('section-lessons').click()
  await expect(page.getByTestId('lesson-item-1')).toHaveAttribute('aria-current', 'true')
  await expect(page.getByTestId('engine-state')).toContainText(/finished/)
  await expect(page.locator('[data-testid^=diagram-message-]').first()).toBeVisible()
})

test('the mode switch sits inside Lessons, and Tour and Free play still switch', async ({ page }) => {
  await open(page)
  await page.getByTestId('lesson-item-1').click()
  await expect(page.getByTestId('top-bar').getByTestId('mode-switch')).toHaveCount(0)
  await page.getByTestId('mode-free').click()
  await expect(page.getByTestId('event-log')).toBeVisible()
  await page.getByTestId('mode-tour').click()
  await expect(page.getByTestId('tour-panel')).toBeVisible()
})

// 1366 and 1536 sit in the band where the brand name hides: the bar must keep its row there too.
for (const size of [{ width: 1280, height: 640 }, { width: 1366, height: 768 }, { width: 1440, height: 770 }, { width: 1536, height: 760 }, { width: 1984, height: 1030 }]) {
  test(`at ${size.width} x ${size.height} the top bar keeps one row with the 3 sections, in every section`, async ({ page }) => {
    await page.setViewportSize(size)
    await open(page)
    for (const s of SECTIONS) {
      await page.getByTestId(`section-${s}`).click()
      expect(await barRows(page), `bar rows in ${s}`).toBe(1)
    }
  })
}

// The AES walk lives in Techniques. A switch to another section never leaves it on screen (Jared, #226).
test('the AES walk shows only in Techniques, and another section never shows it on top', async ({ page }) => {
  await runFreePlay(page, 1)
  await page.getByTestId('aes-walk-tab').click()
  await expect(page.getByTestId('section-techniques')).toHaveAttribute('aria-pressed', 'true')
  await expect(page.getByTestId('aes-walk-panel')).toBeVisible()
  await expect(page.getByTestId('section-placeholder')).toHaveCount(0)
  for (const s of ['handshake', 'lessons'] as const) {
    await page.getByTestId(`section-${s}`).click()
    await expect(page.getByTestId('walk-root'), `in ${s}`).toHaveCount(0)
    await expect(page.getByTestId('aes-walk-panel'), `in ${s}`).toHaveCount(0)
  }
  await expect(page.getByTestId('lesson-item-1')).toHaveAttribute('aria-current', 'true')
  await page.getByTestId('section-techniques').click()
  await expect(page.getByTestId('aes-walk-panel'), 'the walk comes back in Techniques').toBeVisible()
})
