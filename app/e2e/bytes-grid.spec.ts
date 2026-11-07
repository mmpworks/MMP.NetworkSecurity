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

const LOCKED = 'locked: the eavesdropper has no key'
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
    await expect(row).toContainText(LOCKED)
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

// Ranges checked against the engine by decryption with each run's own keys. A wrong range in these lessons must fail here.
const RANGES: [number, string, string, string, number][] = [
  [6, 'Sale', 'pinBlock', 'bytes 16 to 31', 16],
  [7, 'ApplicationData', 'cipher', 'bytes 21 to 68', 48],
  [8, 'ServiceRequest', 'encryptedPacket', 'bytes 0 to 31', 32],
]
for (const [lesson, message, field, range, count] of RANGES) {
  test(`lesson ${lesson}: the eavesdropper can pick ${field} of ${message}, ${range}`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 800 })
    await freePlay(page, lesson)
    await pick(page, message)
    await page.getByTestId('view-eavesdropper').click()
    const row = page.getByTestId(`inspector-field-row-${field}`)
    await expect(row).toContainText(range)
    await expect(row).toContainText(LOCKED)
    await row.click()
    await expect(page.getByTestId('inspector-after').locator('.hb.lit.k-sealed')).toHaveCount(count)
  })
}

test('an event with no wire bytes shows the eavesdropper no bytes and no rows', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 800 })
  await freePlay(page, 7)
  const id = await page.locator('.statusbar').innerText().then(t => /session (?<id>\S+)/.exec(t)?.groups?.id ?? '')
  const r = await fetch(`http://127.0.0.1:${host.port}/api/sessions/${id}/events`, { headers: { Authorization: `Bearer ${host.token}` } })
  const body = (await r.json()) as { events?: any[] } | any[]
  const rows = (Array.isArray(body) ? body : body.events ?? []).map((f: any) => ({ seq: f.seq, ...(f.event ?? f) }))
  const plainOnly = rows.find((e: any) => e.type === 'tls.record.received' && e.plain && !e.wire)
  expect(plainOnly, 'a received record with readable bytes and no wire bytes').toBeTruthy()
  const text = Buffer.from(plainOnly.plain, 'hex').toString('latin1')
  await page.getByTestId(`event-row-${plainOnly.seq}`).click()
  await page.getByTestId('inspector-tab-bytes').click()
  await expect(page.getByTestId('inspector')).toContainText(text.slice(0, 8))
  await page.getByTestId('view-eavesdropper').click()
  await expect(page.getByTestId('inspector')).not.toContainText(text.slice(0, 8))
  await expect(page.getByTestId('inspector').locator('.field-row')).toHaveCount(0)
  await expect(page.getByTestId('inspector-no-wire')).toHaveText('This step happens inside an endpoint, so a listener sees nothing of it.')
})

// What each side knows: a row never sits under the box below it, and the panel has one scroll. A short lesson fits with no scroll at 1440 wide.
const secretsLayout = (page: Page) => page.evaluate(() => {
  const panel = document.querySelector('[data-testid=secrets-panel]')!
  const box = (e: Element) => e.getBoundingClientRect()
  const rows = [...panel.querySelectorAll('.secret-row')].map(box)
  const below = [...panel.querySelectorAll('.converge')].map(box)
  const clips = [...panel.querySelectorAll('.secret-cols')].filter(e => e.scrollHeight > e.clientHeight + 1).length
  return {
    rows: rows.length,
    rowsUnderBox: rows.filter(r => below.some(b => r.bottom > b.top + 1 && r.top < b.bottom - 1)).length,
    innerScrollers: clips,
    shown: panel.clientHeight, whole: panel.scrollHeight,
    rowTexts: [...panel.querySelectorAll('.secret-row')].filter(e => e.scrollWidth > e.clientWidth + 1).length,
  }
})

for (const size of [{ width: 1440, height: 760 }, { width: 1536, height: 760 }, { width: 1440, height: 900 }, { width: 1280, height: 800 }, { width: 1100, height: 800 }]) {
  test(`at ${size.width} x ${size.height} no key row sits under the match box`, async ({ page }) => {
    await page.setViewportSize(size)
    await freePlay(page, 1)
    await pick(page, 'TextGcm1')
    const m = await secretsLayout(page)
    expect(m.rows, 'key rows on screen').toBeGreaterThan(0)
    expect(m.rowsUnderBox, 'key rows under the match box').toBe(0)
    expect(m.innerScrollers, 'a second scroll inside the panel').toBe(0)
    expect(m.rowTexts, 'cut row text').toBe(0)
    if (size.width >= 1440) expect(m.whole, 'the panel scrolls on a short lesson').toBeLessThanOrEqual(m.shown + 1)
  })
}

// The line between the 2 grids says what happened to the bytes. A grid that is too short for its own rows must not paint them over that line.
// The app sets its pane shares when the window opens, so each size runs twice: opened at that size, and opened at 1440 x 770 and then resized, as a learner does.
for (const [size, resized] of [[{ width: 1440, height: 770 }, false], [{ width: 1280, height: 640 }, false], [{ width: 1280, height: 640 }, true]] as const) {
  test(`at ${size.width} x ${size.height}${resized ? ', resized from 1440 x 770,' : ''} the "locked with the key, then sent" line covers no hex row`, async ({ page }) => {
    await page.setViewportSize(resized ? { width: 1440, height: 770 } : size)
    await freePlay(page, 1)
    await pick(page, 'TextGcm1')
    if (resized) { await page.setViewportSize(size); await page.waitForTimeout(500) }
    await expect(page.locator('.became')).toHaveText(/locked with the key, then sent/)
    const hits = await page.evaluate(() => {
      const line = document.querySelector('.became')!.getBoundingClientRect()
      return [...document.querySelectorAll('.inspector .hex-scroll')].map(e => e.getBoundingClientRect()).filter(r => r.bottom > line.top + 1 && r.top < line.bottom - 1).length
    })
    expect(hits, 'hex grids that reach into the line').toBe(0)
  })
}

// Binary hover: every hex byte cell, in the bytes panel and in the match grids, shows its byte in binary.
test('a hex byte in the bytes panel and in a match grid shows its binary on hover', async ({ page }) => {
  await freePlay(page, 1)
  await pick(page, 'TextGcm1')
  const tip = page.getByTestId('binary-tip')
  const first = page.locator('[data-testid^=inspector-byte-]').first()
  const text = (await first.textContent())!.trim()
  await first.hover()
  await expect(tip).toHaveText(`${text} = ${parseInt(text, 16).toString(2).padStart(8, '0').replace(/^(?<hi>.{4})/, '$<hi> ')}`)
  const cell = page.locator('[data-testid^=convergence-grid-] .cell').first()
  const c = (await cell.textContent())!.trim()
  await cell.hover()
  await expect(tip).toContainText(`${c} = `)
  await page.mouse.move(5, 300)
  await expect(tip).toHaveCount(0)
  const unmarked = await page.evaluate(() => [...document.querySelectorAll('.inspector .hb, .grid32 .cell')].filter(e => !e.hasAttribute('data-hex-byte')).length)
  expect(unmarked, 'hex cells with no binary hover').toBe(0)
})
