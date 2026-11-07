import { expect, test, type Page } from '@playwright/test'
import { runFreePlay } from './walk'

// Layout in every view at every size Steve uses. Lesson 3 holds the longest field and key names, so a narrow column shows first there.
// 1984 x 1030 is Steve's window (1984 x 1086) less Electron's title bar and menu bar.
const SIZES = [{ width: 1280, height: 640 }, { width: 1440, height: 770 }, { width: 1984, height: 1030 }]
const VIEWS = ['endpoints', 'eavesdropper', 'both'] as const

// Text that is meant to wrap anywhere: hex, key values, code. A label is any other text.
const FREE_TEXT = 'code, pre, svg, input, textarea, select, .hex-scroll, .grid32, .fval, .wiz-out, .v-overlay-container'

interface Fault { kind: string; where: string; text: string }

const scan = (page: Page) => page.evaluate((freeText: string) => {
  const faults: { kind: string; where: string; text: string }[] = []
  const root = document.querySelector('[data-testid=app-root]')!
  const name = (e: Element) => (e.getAttribute('data-testid') ?? '') || `${e.tagName.toLowerCase()}.${String(e.className).split(' ').filter(Boolean).slice(0, 2).join('.')}`
  // 1. A word in a label never breaks across 2 lines.
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT)
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    const parent = n.parentElement
    if (!parent || parent.closest(freeText)) continue
    const text = n.textContent ?? ''
    for (const m of text.matchAll(/\S{3,}/g)) {
      const r = document.createRange()
      r.setStart(n, m.index!)
      r.setEnd(n, m.index! + m[0].length)
      const tops = new Set([...r.getClientRects()].filter(b => b.width > 0).map(b => Math.round(b.top)))
      if (tops.size > 1) faults.push({ kind: 'word broken', where: name(parent), text: m[0] })
    }
  }
  // 2. Nothing sticks out of a box that clips it without a scrollbar, or out of its panel.
  const panels = [...root.querySelectorAll('.panel, .topbar, .rail')]
  for (const panel of panels) {
    for (const el of panel.querySelectorAll('*')) {
      const b = el.getBoundingClientRect()
      if (b.width === 0 || b.height === 0 || el.closest(freeText) || el.closest('.v-btn__overlay, .v-btn__underlay')) continue
      let clip: Element = panel
      for (let a = el.parentElement; a && a !== panel; a = a.parentElement) {
        const s = getComputedStyle(a)
        if (s.overflowX !== 'visible') { clip = a; break }
      }
      const s = getComputedStyle(clip)
      if (clip !== panel && (s.overflowX === 'auto' || s.overflowX === 'scroll')) continue
      const c = clip.getBoundingClientRect()
      if (b.right > c.right + 1 || b.left < c.left - 1) faults.push({ kind: 'sticks out', where: `${name(el)} in ${name(clip)}`, text: (el.textContent ?? '').trim().slice(0, 30) })
    }
  }
  // 3. A diagram fills its pane: the lane band and the row highlight span the whole width.
  for (const sc of root.querySelectorAll('.diagram-scroll')) {
    const svg = sc.querySelector('svg')
    if (svg && svg.getBoundingClientRect().width < sc.clientWidth - 2) faults.push({ kind: 'diagram short', where: name(sc.closest('[data-testid]') ?? sc), text: `${Math.round(svg.getBoundingClientRect().width)} of ${sc.clientWidth}` })
  }
  // 5. A button never cuts its label.
  for (const b of root.querySelectorAll('.v-btn')) { const r = b.getBoundingClientRect(); if (r.width > 0 && b.scrollHeight > b.clientHeight + 1) faults.push({ kind: 'label cut', where: name(b), text: (b.textContent ?? '').trim().slice(0, 30) }) }
  // 6. A key card keeps its size and its buttons on one line.
  for (const row of root.querySelectorAll('.secret-row')) {
    const tops = [...row.querySelectorAll(':scope > .muted, :scope > .v-btn')].map(e => Math.round(e.getBoundingClientRect().top + e.getBoundingClientRect().height / 2))
    if (tops.length > 1 && Math.max(...tops) - Math.min(...tops) > 4) faults.push({ kind: 'card line split', where: name(row), text: '' })
  }
  // 4. A field name shows whole.
  for (const f of root.querySelectorAll('.field-row .fname')) if (f.scrollWidth > f.clientWidth + 1) faults.push({ kind: 'name cut', where: name(f.closest('[data-testid]') ?? f), text: (f.textContent ?? '').trim() })
  return faults
}, FREE_TEXT)

const unique = (list: Fault[]) => [...new Map(list.map(f => [`${f.kind}|${f.where}|${f.text}`, f])).values()].map(f => `${f.kind}: ${f.where} "${f.text}"`)

for (const size of SIZES) {
  test(`at ${size.width} x ${size.height}, lesson 3 in all 3 views: no broken word, nothing sticks out, the diagrams fill their panes`, async ({ page }) => {
    test.setTimeout(120_000)
    await page.setViewportSize(size)
    await runFreePlay(page, 3)
    await page.locator('[data-testid^=diagram-message-]', { hasText: /MlKemCiphertext/i }).first().click()
    const tab = page.getByTestId('inspector-tab-bytes')
    if (await tab.count()) await tab.click()
    const all: string[] = []
    for (const view of VIEWS) {
      await page.getByTestId(`view-${view}`).click()
      await page.waitForTimeout(700)
      all.push(...unique(await scan(page)).map(f => `${view}: ${f}`))
    }
    expect(all, `layout faults at ${size.width} x ${size.height}`).toEqual([])
  })
}
