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
    // A dot, an underscore or a hyphen joins 2 words, so a break there is between words.
    for (const m of text.matchAll(/[^\s._-]{3,}/g)) {
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
  // 9. A diagram never scrolls sideways: it fits its pane (closer lanes, then a fitted zoom). A part-pixel overflow still draws a full bar,
  // so the check tries to scroll and reads whether the box moved, which scrollWidth alone rounds away.
  for (const sc of root.querySelectorAll<HTMLElement>('.diagram-scroll')) {
    const before = sc.scrollLeft
    sc.scrollLeft = 10_000
    const moved = sc.scrollLeft
    sc.scrollLeft = before
    if (moved > 0) faults.push({ kind: 'diagram scrolls sideways', where: name(sc.closest('[data-testid]') ?? sc), text: `${moved.toFixed(2)} px` })
  }
  // 10. A diagram's text stays readable at a fitted zoom: labels at least 10 px on screen, byte counts at least 9 px. And a message
  // label never runs past the 2 lanes of its arrow, at any lane spacing (gap 160 at the narrowest).
  for (const svg of root.querySelectorAll<SVGSVGElement>('.diagram-scroll svg')) {
    const vb = svg.viewBox.baseVal
    const shown = svg.getBoundingClientRect().width
    // A hidden diagram (the lesson panes behind Techniques) has no size on screen, so it has no text size to read.
    if (!vb || vb.width === 0 || shown === 0) continue
    const scale = shown / vb.width
    const where = name(svg.closest('[data-testid]') ?? svg)
    for (const [selector, min] of [['.arrow-label, .chk-name, .lane-name', 10], ['.arrow-sub, .chip-text', 9]] as const) {
      for (const t of svg.querySelectorAll<SVGTextElement>(selector)) {
        const px = parseFloat(getComputedStyle(t).fontSize) * scale
        if (px < min - 0.05) { faults.push({ kind: 'diagram text too small', where, text: `${(t.textContent ?? '').trim().slice(0, 20)} ${px.toFixed(1)} px` }); break }
      }
    }
    for (const t of svg.querySelectorAll<SVGTextElement>('.arrow-label')) {
      const line = t.parentElement?.querySelector<SVGLineElement>('line.arrow')
      if (!line) continue
      // The line stops 8 units short of the far lane for its arrow head, so the 2 lanes stand 8 units further apart than the line is long.
      const gap = Math.abs(line.x2.baseVal.value - line.x1.baseVal.value) + 8
      if (t.getBBox().width > gap) faults.push({ kind: 'label wider than its lanes', where, text: (t.textContent ?? '').trim().slice(0, 30) })
    }
  }
  // 5. A button never cuts its label.
  // Height and width: a label can be cut at the bottom or at the side.
  for (const b of root.querySelectorAll('.v-btn')) { const r = b.getBoundingClientRect(); if (r.width > 0 && (b.scrollHeight > b.clientHeight + 1 || b.scrollWidth > b.clientWidth + 1)) faults.push({ kind: 'label cut', where: name(b), text: (b.textContent ?? '').trim().slice(0, 30) }) }
  // 6. A key card keeps its size and its buttons on one line.
  for (const row of root.querySelectorAll('.secret-row')) {
    const tops = [...row.querySelectorAll(':scope > .muted, :scope > .v-btn')].map(e => Math.round(e.getBoundingClientRect().top + e.getBoundingClientRect().height / 2))
    if (tops.length > 1 && Math.max(...tops) - Math.min(...tops) > 4) faults.push({ kind: 'card line split', where: name(row), text: '' })
  }
  // 7. In a wide bytes panel the field list sits beside the grids, and each field row shows its value line.
  for (const insp of root.querySelectorAll('.inspector')) {
    if (insp.getBoundingClientRect().width < 700) continue
    for (const v of insp.querySelectorAll('.field-row .fval')) if (v.getBoundingClientRect().height === 0) faults.push({ kind: 'value hidden', where: name(v.closest('[data-testid]') ?? v), text: '' })
  }
  // 8. A line marked data-show-whole is never cut: not by its own box, and not by any box around it that clips or scrolls.
  // A scrolling box would let it scroll out of sight, which cuts it as surely as a clip (the AES strip's legend, #270).
  for (const el of root.querySelectorAll('[data-show-whole]')) {
    const b = el.getBoundingClientRect()
    if (b.width === 0) continue
    if (el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1) { faults.push({ kind: 'cut', where: name(el), text: (el.textContent ?? '').trim().slice(0, 30) }); continue }
    for (let a = el.parentElement; a && a !== root; a = a.parentElement) {
      const s = getComputedStyle(a)
      if (s.overflowX === 'visible' && s.overflowY === 'visible') continue
      const c = a.getBoundingClientRect()
      if (b.right > c.right + 1 || b.left < c.left - 1 || b.bottom > c.bottom + 1 || b.top < c.top - 1) { faults.push({ kind: 'cut', where: `${name(el)} in ${name(a)}`, text: (el.textContent ?? '').trim().slice(0, 30) }); break }
    }
  }
  // 4. A field name shows whole.
  for (const f of root.querySelectorAll('.field-row .fname, .secret-row > .sname')) if (f.scrollWidth > f.clientWidth + 1) faults.push({ kind: 'name cut', where: name(f.closest('[data-testid]') ?? f), text: (f.textContent ?? '').trim() })
  return faults
}, FREE_TEXT)

const unique = (list: Fault[]) => [...new Map(list.map(f => [`${f.kind}|${f.where}|${f.text}`, f])).values()].map(f => `${f.kind}: ${f.where} "${f.text}"`)

// Each lesson with the message it picks: lesson 3 for the longest field names, 1 for the first bytes a learner sees, 5 for the certificate chain, 10 for the token panel.
const LESSONS: [number, RegExp | null][] = [[3, /MlKemCiphertext/i], [1, /TextGcm1/], [5, null], [10, null]]

for (const size of SIZES) {
  test(`at ${size.width} x ${size.height}, lessons 3, 1, 5 and 10 in all 3 views: no broken word, nothing sticks out, the diagrams fill their panes`, async ({ page }) => {
    test.setTimeout(240_000)
    await page.setViewportSize(size)
    const all: string[] = []
    for (const [lesson, message] of LESSONS) {
      await runFreePlay(page, lesson)
      if (message) await page.locator('[data-testid^=diagram-message-]', { hasText: message }).first().click()
      for (const view of VIEWS) {
        await page.getByTestId(`view-${view}`).click()
        await page.waitForTimeout(700)
        // Every tab that this lesson shows, in this view.
        const tabs = await page.locator('[data-testid^=inspector-tab-]').evaluateAll(list => list.map(t => t.getAttribute('data-testid')!))
        for (const tab of tabs.length ? tabs : ['']) {
          if (tab) { await page.getByTestId(tab).click(); await page.waitForTimeout(300) }
          all.push(...unique(await scan(page)).map(f => `lesson ${lesson}, ${view}${tab ? ', ' + tab.replace('inspector-tab-', '') : ''}: ${f}`))
        }
      }
      await page.getByTestId('view-endpoints').click()
    }
    expect([...new Set(all)], `layout faults at ${size.width} x ${size.height}`).toEqual([])
  })

  // Techniques: the AES walk with its long-text strip, which holds the lesson text's 5 blocks, the widest default row.
  test(`at ${size.width} x ${size.height}, Techniques AES with the long-text strip: no broken word, nothing cut`, async ({ page }) => {
    await page.setViewportSize(size)
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await runFreePlay(page, 1)
    await page.getByTestId('section-techniques').click()
    await page.getByTestId('walk-item-aes').click()
    await expect(page.getByTestId('aes-long-block-4'), 'the strip holds the lesson text\'s 5 blocks').toBeVisible({ timeout: 30_000 })
    await expect(page.getByTestId('aes-walk-step-kind')).toBeVisible({ timeout: 30_000 })
    const faults = unique(await scan(page))
    expect(faults, `layout faults in Techniques at ${size.width} x ${size.height}`).toEqual([])
  })
}
