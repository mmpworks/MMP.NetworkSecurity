import { expect, test, type Page } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { scanPage, setTheme } from './contrast'
import { startOwnHost, type OwnHost } from './own-host'
import { open } from './walk'

// The Message bytes panel keeps one grid: every byte column and the text column sit at one x, on every row of Before and After.
// Field boundaries show by color, never by added space, and nothing in the panel overflows. This runs several messages at 3 window widths.
const OUT = path.join(__dirname, '..', 'test-results', 'bytes-grid')
const shot = async (page: Page, name: string) => { fs.mkdirSync(OUT, { recursive: true }); await page.getByTestId('inspector').screenshot({ path: path.join(OUT, `${name}.png`) }) }

let host: OwnHost
test.beforeAll(async () => { host = await startOwnHost() })
test.afterAll(async () => { await host.stop() })

async function freePlay(page: Page, lesson: number) {
  await open(page, host)
  await page.getByTestId(`lesson-item-${lesson}`).click()
  await page.getByTestId('mode-free').click()
  await page.getByTestId('free-start').click()
  await page.getByTestId('free-run').click()
  await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 60_000 })
}

const pick = async (page: Page, message: string) => {
  await page.locator('[data-testid^=diagram-message-]', { hasText: message }).first().click({ timeout: 8000 })
  await page.getByTestId('inspector-tab-bytes').click()
  await page.waitForTimeout(900)
}

const measure = (page: Page) => page.evaluate(() => {
  const round = (n: number) => Math.round(n * 2) / 2
  const columns = new Map<number, Set<number>>()
  const text = new Set<number>()
  const rows = [...document.querySelectorAll('.hex-row')]
  for (const row of rows) {
    ;[...row.querySelectorAll('.hb')].forEach((b, i) => {
      columns.set(i, (columns.get(i) ?? new Set<number>()).add(round(b.getBoundingClientRect().left)))
    })
    const a = row.querySelector('.hex-ascii')
    if (a) text.add(round(a.getBoundingClientRect().left))
  }
  const panel = document.querySelector('[data-testid=inspector]')!.getBoundingClientRect()
  const past = (s: string) => [...document.querySelectorAll(s)].filter(e => e.getBoundingClientRect().right > panel.right + 1 && (e as HTMLElement).offsetParent !== null).map(e => (e.textContent ?? '').trim().slice(0, 24))
  const cut = (s: string) => [...document.querySelectorAll(s)].filter(e => e.scrollWidth > e.clientWidth + 1).map(e => (e.textContent ?? '').trim().slice(0, 24))
  return {
    rows: rows.length,
    columnsWithTwoPlaces: [...columns.entries()].filter(([, xs]) => xs.size > 1).map(([i, xs]) => `${i}: ${[...xs].join(' ')}`),
    textPlaces: [...text],
    pastTheEdge: [...past('[data-testid=inspector] .inspector-tools > *'), ...past('.field-list > *'), ...past('.grid-head')],
    cutText: [...cut('.field-row .fname'), ...cut('.field-row'), ...cut('[data-testid=inspector] .inspector-tools')],
    gridCut: [...document.querySelectorAll('.hex-scroll')].filter(e => e.scrollWidth > e.clientWidth + 1).length,
  }
})

function expectOneGrid(m: Awaited<ReturnType<typeof measure>>, where: string) {
  expect(m.rows, `${where}: rows on screen`).toBeGreaterThan(0)
  expect(m.columnsWithTwoPlaces, `${where}: a byte column sits at two x values`).toEqual([])
  expect(m.textPlaces, `${where}: the text column sits at more than one x`).toHaveLength(1)
  expect(m.pastTheEdge, `${where}: past the panel edge`).toEqual([])
  expect(m.cutText, `${where}: cut text`).toEqual([])
  expect(m.gridCut, `${where}: a hex row cut at the right`).toBe(0)
}

const MESSAGES: [number, string[]][] = [[1, ['TextGcm1', 'TextCbc', 'PictureEcb']], [5, ['ClientHello', 'Finished']], [8, ['KEXINIT']]]
for (const width of [1100, 1280, 1440]) {
  test(`at ${width} wide every byte column and the text column line up, and nothing overflows`, async ({ page }) => {
    test.setTimeout(180_000)
    await page.setViewportSize({ width, height: 800 })
    for (const [lesson, names] of MESSAGES) {
      await freePlay(page, lesson)
      for (const name of names) {
        await pick(page, name)
        expectOneGrid(await measure(page), `${width} lesson ${lesson} ${name}`)
        if (lesson === 1 && name === 'TextGcm1') {
          await shot(page, `grid-${width}`)
          // A short message fits with no cut row. A long one scrolls inside its grid.
          const tall = await page.locator('.hex-scroll').evaluateAll(all => all.filter(e => e.scrollHeight > e.clientHeight + 1).length)
          expect(tall, `${width}: a hex row of TextGcm1 is cut at the bottom`).toBe(0)
        }
      }
      // The eavesdropper's arrow hides the message name, so the message is picked first.
      await pick(page, names[0])
      await page.getByTestId('view-eavesdropper').click()
      await page.waitForTimeout(300)
      expectOneGrid(await measure(page), `${width} lesson ${lesson} ${names[0]} eavesdropper`)
      await page.getByTestId('view-endpoints').click()
    }
  })
}

for (const theme of ['light', 'dark'] as const) {
  test(`the eavesdropper can pick the ciphertext and see the bytes it fills, in the ${theme} theme`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 800 })
    await freePlay(page, 1)
    await setTheme(page, theme)
    await pick(page, 'TextGcm1')
    await page.getByTestId('view-eavesdropper').click()
    await page.waitForTimeout(300)
    await shot(page, `eavesdropper-${theme}-at-rest`)
    const row = page.getByTestId('inspector-field-row-cipher')
    await expect(row).toContainText('bytes 16 to 79')
    await expect(row).toContainText('unreadable without the key')
    await expect(page.getByTestId('inspector-field-value-cipher')).not.toHaveText('')
    await row.click()
    await expect(row).toHaveAttribute('aria-pressed', 'true')
    const lit = page.getByTestId('inspector-after').locator('.hb.lit')
    await expect(lit).toHaveCount(64)
    await expect(page.getByTestId('inspector-byte-16')).toHaveClass(/k-sealed/)
    await expect(page.getByTestId('inspector-byte-79')).toHaveClass(/k-sealed/)
    await expect(page.getByTestId('inspector-byte-15')).not.toHaveClass(/\blit\b/)
    await expect(page.getByTestId('inspector-byte-80')).not.toHaveClass(/\blit\b/)
    await page.waitForTimeout(300)
    await shot(page, `eavesdropper-${theme}-picked`)
    const s = await scanPage(page)
    expect(s.fails, JSON.stringify(s.fails.slice(0, 5))).toEqual([])
  })
}
