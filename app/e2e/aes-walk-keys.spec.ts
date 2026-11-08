import { expect, test, type Page } from '@playwright/test'
import { scanPage, setTheme } from './contrast'
import { open } from './walk'

// Steve's 3 fixes to the AES walk, to match the approved mock (E:/dev/ns-mock/design/mock/, the published copy): the block cells show
// their index and character; the key schedule builds each word in motion, in the mock's landscape layout; and the key schedule zooms.
// Test ids follow Echo's #317.

const STAGES = ['previous', 'rotated', 'substituted', 'rcon', 'after-rcon', 'key-back', 'word']
const stageRows = (page: Page) => page.locator(STAGES.map(s => `[data-testid="aes-walk-build-${s}"]`).join(', '))

async function openPractice(page: Page) {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await open(page)
  await page.getByTestId('section-techniques').click()
  await page.getByTestId('walk-item-aes').click()
  await expect(page.getByTestId('aes-walk-step-kind')).toBeVisible()
}

/** Moves to stop n from the start, under reduced motion, so each Next lands at once. */
async function toStop(page: Page, n: number) {
  for (let i = 0; i < n; i++) await page.getByTestId('aes-walk-next').click()
}
const FILL_END = 16
const KEYS = FILL_END + 1

/** The character rule from the strip legend: "sp" for a space, the character for printable ASCII, and a dot for any other byte. */
const charOf = (hex: string) => { const n = parseInt(hex, 16); return n === 0x20 ? 'sp' : n > 0x20 && n < 0x7f ? String.fromCharCode(n) : '·' }

test('each block cell shows its byte index and its character, and an empty cell shows its index only', async ({ page }) => {
  await openPractice(page)
  await toStop(page, 3)
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) {
    const i = r + 4 * c, id = `aes-walk-cell-${r}-${c}`
    await expect(page.getByTestId(`${id}-index`), `${id} index`).toHaveText(String(i))
    if (i >= 3) {
      await expect(page.getByTestId(id), `${id} is empty`).toHaveAttribute('data-hex', '')
      await expect(page.getByTestId(`${id}-char`)).toHaveText('')
    }
  }
  await toStop(page, FILL_END - 3)
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) {
    const id = `aes-walk-cell-${r}-${c}`
    const hex = (await page.getByTestId(id).getAttribute('data-hex')) ?? ''
    expect(hex, `${id} holds a byte`).toMatch(/^[0-9a-f]{2}$/)
    expect((await page.getByTestId(id).textContent())?.trim().slice(0, 2), `${id} reads its hex first`).toBe(hex)
    await expect(page.getByTestId(`${id}-char`), `${id} char of ${hex}`).toHaveText(charOf(hex))
  }
})

test('with motion on, Next onto a word shows the build rows one after another, then fills its 4 bytes one at a time', async ({ page }) => {
  await openPractice(page)
  await toStop(page, KEYS)
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  await page.getByTestId('aes-walk-next').click()
  const cells = [16, 17, 18, 19].map(n => page.getByTestId(`aes-walk-table-cell-${n}`))
  const samples: { t: number; rows: number; filled: number; xor: string }[] = []
  const start = Date.now()
  while (Date.now() - start < 20_000) {
    const rows = await stageRows(page).count()
    let filled = 0
    for (const c of cells) if ((await c.getAttribute('data-hex')) ?? '') filled++
    const xor = (await page.getByTestId('aes-walk-build-xor').count()) ? ((await page.getByTestId('aes-walk-build-xor').textContent()) ?? '') : ''
    samples.push({ t: Date.now() - start, rows, filled, xor })
    if (filled === 4 && rows === STAGES.length) break
    await page.waitForTimeout(40)
  }
  const last = samples[samples.length - 1]
  expect(last, 'the build ends with every row and all 4 bytes').toMatchObject({ rows: STAGES.length, filled: 4 })
  expect(samples[0].rows, 'the rows do not all appear in one frame').toBeLessThan(STAGES.length)
  const allRows = samples.find(s => s.rows === STAGES.length)!
  expect(allRows.t - samples[0].t, 'the rows take at least 300 ms').toBeGreaterThanOrEqual(300)
  expect(samples.filter(s => s.filled > 0).every(s => s.rows === STAGES.length), 'the bytes fill after the rows').toBe(true)
  expect(new Set(samples.map(s => s.filled)), 'the bytes fill one at a time').toEqual(new Set([0, 1, 2, 3, 4]))
  // The byte XOR line: byte 0 of w0, the value it meets, and byte 0 of w4, each as 8 bits.
  const bits = (hex: string) => parseInt(hex, 16).toString(2).padStart(8, '0')
  const valueOf = async (stage: string) => ((await page.getByTestId(`aes-walk-build-${stage}`).locator('code').textContent()) ?? '').replace(/\s+/g, '')
  const back = await valueOf('key-back'), meets = await valueOf('after-rcon'), word = await valueOf('word')
  for (const v of [back, meets, word]) expect(v, 'a stage row holds 4 bytes').toMatch(/^[0-9a-f]{8}$/)
  const frame = samples.map(s => s.xor.replace(/\s+/g, '')).find(x => x.includes(bits(back.slice(0, 2))) && x.includes(bits(meets.slice(0, 2))) && x.includes(bits(word.slice(0, 2))))
  expect(frame, 'one frame shows byte 0 of w0, the value it meets, and byte 0 of w4, in bits').toBeTruthy()
})

// The lead on #326: each finished byte flies from the XOR line into its cell, as the mock does, and on a short window the step in play
// stays in view.
test('each finished byte flies from the XOR line into its cell, and at 1280 x 640 the rows and the XOR line stay in view', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 640 })
  await openPractice(page)
  await toStop(page, KEYS)
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  // The page records every frame, so a 520 ms flight gives many samples. A row or the XOR line counts once it has been on screen 400 ms,
  // the time a scroll into view takes to settle.
  await page.evaluate(() => {
    const w = window as any
    w.__flights = []; w.__out = []
    const since = new Map<Element, number>()
    const tick = () => {
      const f = document.querySelector('[data-testid="aes-walk-ks-flyer"]')
      if (f) { const b = f.getBoundingClientRect(); w.__flights.push({ text: (f.textContent ?? '').trim(), x: b.x, y: b.y }) }
      const rows = document.querySelectorAll('.aw-ks-stage')
      for (const el of [rows[rows.length - 1], document.querySelector('[data-testid="aes-walk-build-xor"]')]) {
        if (!el) continue
        if (!since.has(el)) since.set(el, performance.now())
        const b = el.getBoundingClientRect()
        if (performance.now() - since.get(el)! > 400 && (b.top < 0 || b.bottom > innerHeight)) w.__out.push(`${el.getAttribute('data-testid')} at ${Math.round(b.top)} to ${Math.round(b.bottom)}`)
      }
      if (!w.__stop) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  })
  await page.getByTestId('aes-walk-next').click()
  await expect(page.getByTestId('aes-walk-table-cell-19')).not.toHaveAttribute('data-hex', '', { timeout: 20_000 })
  await expect(page.getByTestId('aes-walk-build-xor')).toHaveCount(0, { timeout: 5_000 })
  const { flights, outOfView } = await page.evaluate(() => { const w = window as any; w.__stop = true; return { flights: w.__flights as { text: string; x: number; y: number }[], outOfView: [...new Set(w.__out as string[])] } })
  const word = ((await page.getByTestId('aes-walk-build-word').locator('code').textContent()) ?? '').replace(/\s+/g, '')
  const first = flights.filter(f => f.text === word.slice(0, 2))
  expect(first.length, `byte 0 (${word.slice(0, 2)}) flies`).toBeGreaterThan(1)
  expect(Math.hypot(first[first.length - 1].x - first[0].x, first[first.length - 1].y - first[0].y), 'the byte moves toward its cell').toBeGreaterThan(20)
  expect(new Set(flights.map(f => f.text)).size, 'all 4 bytes fly').toBe(4)
  expect(outOfView, 'the newest row and the XOR line stay inside the window').toEqual([])
})

test('the word built, the word before and the word Nk back each carry their role and their own color, in the grid and in the rows', async ({ page }) => {
  await openPractice(page)
  await toStop(page, KEYS + 1)
  const roleOf = async (word: number) => page.getByTestId(`aes-walk-table-cell-${4 * word}`).getAttribute('data-role')
  expect(await roleOf(4)).toBe('new')
  expect(await roleOf(3)).toBe('previous')
  expect(await roleOf(0)).toBe('key-back')
  expect(await roleOf(1)).toBeNull()
  const bg = (id: string) => page.getByTestId(id).evaluate(el => getComputedStyle(el).backgroundColor)
  const colors = [await bg('aes-walk-table-cell-16'), await bg('aes-walk-table-cell-12'), await bg('aes-walk-table-cell-0'), await bg('aes-walk-table-cell-4')]
  expect(new Set(colors).size, 'new, previous, key-back and a plain cell: 4 different colors').toBe(4)
  expect(await bg('aes-walk-build-word')).toBe(colors[0])
  expect(await bg('aes-walk-build-previous')).toBe(colors[1])
  expect(await bg('aes-walk-build-key-back')).toBe(colors[2])
})

test('the round-constant strip lights the constant a rotating word uses, and none for a plain word', async ({ page }) => {
  await openPractice(page)
  await toStop(page, KEYS + 1)
  await expect(page.getByTestId('aes-walk-rcon-0')).toHaveAttribute('data-lit', 'true')
  await expect(page.locator('[data-testid^="aes-walk-rcon-"][data-lit="true"]')).toHaveCount(1)
  // FIPS 197 numbers the round constants from 1: w4 uses Rcon[1] = 01, so its label reads 1, while the chip list counts from 0 (Richard on #326).
  await expect(page.getByTestId('aes-walk-build-rcon')).toContainText('Round constant 1')
  await expect(page.getByTestId('aes-walk-build-rcon').locator('code')).toHaveText(/01\s*00\s*00\s*00/)
  await toStop(page, 4)
  await expect(page.getByTestId('aes-walk-ks-build-title')).toHaveText('How w8 is made')
  await expect(page.getByTestId('aes-walk-build-rcon')).toContainText('Round constant 2')
  await expect(page.getByTestId('aes-walk-rcon-1')).toHaveAttribute('data-lit', 'true')
  await toStop(page, 1)
  await expect(page.locator('[data-testid^="aes-walk-rcon-"][data-lit="true"]')).toHaveCount(0)
})

test('a tap on a built word replays its build, and the title names it', async ({ page }) => {
  await openPractice(page)
  await toStop(page, KEYS + 3)
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  await page.getByTestId('aes-walk-table-cell-16').click()
  await expect(page.getByTestId('aes-walk-ks-build-title')).toHaveText('How w4 is made')
  const first = await stageRows(page).count()
  expect(first, 'the replay starts without every row').toBeLessThan(STAGES.length)
  await expect(stageRows(page)).toHaveCount(STAGES.length, { timeout: 10_000 })
})

for (const theme of ['light', 'dark'] as const) {
  test(`the block's corners, the role colors and the build panel read at 4.5 to 1 in the ${theme} theme`, async ({ page }) => {
    await openPractice(page)
    await setTheme(page, theme)
    await toStop(page, FILL_END)
    let s = await scanPage(page)
    expect(s.fails, `block: ${JSON.stringify(s.fails.slice(0, 5))}`).toEqual([])
    await toStop(page, 2)
    s = await scanPage(page)
    expect(s.checked, 'the scan read the key schedule').toBeGreaterThan(100)
    expect(s.fails, `key schedule: ${JSON.stringify(s.fails.slice(0, 5))}`).toEqual([])
  })
}

// Steve on #326 (AES-256, zoom 145%): the round keys scroll in their own box, so the step buttons and the build panel stay on screen while
// he looks at the last round keys. A word that builds scrolls the box, and only the box, to its cells.
const inWindow = async (page: Page, id: string) => {
  const b = (await page.getByTestId(id).boundingBox())!
  const vp = page.viewportSize()!
  return b.y >= 0 && b.y + Math.min(b.height, 40) <= vp.height && b.x >= 0 && b.x + Math.min(b.width, 40) <= vp.width
}
for (const size of [{ width: 1984, height: 1086 }, { width: 1280, height: 640 }]) {
  test(`at ${size.width} x ${size.height}, AES-256 at 145%: the round keys scroll in their own box, and Next word and the panel stay on screen`, async ({ page }) => {
    await page.setViewportSize(size)
    await openPractice(page)
    await page.getByTestId('aes-walk-key-size-256').click()
    await expect(page.getByTestId('aes-walk-step-kind')).toBeVisible()
    await toStop(page, KEYS + 1)
    const zin = page.getByTestId('aes-walk-ks-zoom-in')
    while (await zin.isEnabled()) await zin.click()
    const box = page.getByTestId('aes-walk-ks-table')
    const scrolls = await box.evaluate(el => { const s = getComputedStyle(el); return el.scrollHeight > el.clientHeight && /auto|scroll/.test(s.overflowY) })
    expect(scrolls, 'the round keys scroll inside their own box').toBe(true)
    const pageTop = await page.getByTestId('workspace').evaluate(el => el.scrollTop)
    await box.evaluate(el => { el.scrollTop = el.scrollHeight })
    await expect(page.getByTestId('aes-walk-table-grid-14')).toBeInViewport({ ratio: 0.3 })
    expect(await page.getByTestId('workspace').evaluate(el => el.scrollTop), 'the page does not move').toBe(pageTop)
    expect(await inWindow(page, 'aes-walk-next'), 'Next word stays on screen').toBe(true)
    expect(await inWindow(page, 'aes-walk-ks-build-title'), 'the build panel stays on screen').toBe(true)
    expect(await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth), 'no sideways page scroll').toBe(false)
  })
}

test('when a late word builds, the round-key box scrolls to its cells, and the page stays put', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 640 })
  await openPractice(page)
  await page.getByTestId('aes-walk-key-size-256').click()
  await expect(page.getByTestId('aes-walk-step-kind')).toBeVisible()
  await toStop(page, KEYS)
  const zin = page.getByTestId('aes-walk-ks-zoom-in')
  while (await zin.isEnabled()) await zin.click()
  const pageTop = await page.getByTestId('workspace').evaluate(el => el.scrollTop)
  await toStop(page, 52)
  // w59 is the last word: grid 14, column 3. Its byte 0 is cell 16 * 14 + 4 * 3 = 236.
  await expect(page.getByTestId('aes-walk-ks-build-title')).toHaveText('How w59 is made')
  const boxEl = page.getByTestId('aes-walk-ks-table')
  expect(await boxEl.evaluate(el => el.scrollHeight > el.clientHeight && el.scrollTop > 0), 'the box scrolled down to the last round key').toBe(true)
  const cell = await page.getByTestId('aes-walk-table-cell-236').boundingBox(), area = await boxEl.boundingBox()
  expect(cell!.y >= area!.y - 1 && cell!.y + cell!.height <= area!.y + area!.height + 1, 'w59 is in view inside the box').toBe(true)
  await expect(page.getByTestId('aes-walk-table-cell-236'), 'and on screen').toBeInViewport()
  expect(await page.getByTestId('workspace').evaluate(el => el.scrollTop), 'the page does not move').toBe(pageTop)
})

const noSideways = (page: Page) => page.evaluate(() => {
  const ks = document.querySelector('[data-testid="aes-walk-key-schedule"]') as HTMLElement
  return { page: document.documentElement.scrollWidth > document.documentElement.clientWidth, ks: ks.scrollWidth > ks.clientWidth + 1 }
})

test('the key schedule zooms in and out with buttons and Ctrl and the wheel, resets, and never scrolls sideways at 1280', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 })
  await openPractice(page)
  await toStop(page, KEYS)
  const width = () => page.getByTestId('aes-walk-table-cell-0').evaluate(el => el.getBoundingClientRect().width)
  const base = await width()
  const zin = page.getByTestId('aes-walk-ks-zoom-in'), zout = page.getByTestId('aes-walk-ks-zoom-out')
  while (await zin.isEnabled() && (await width()) < base * 1.2) { await zin.click(); expect(await noSideways(page)).toEqual({ page: false, ks: false }) }
  expect(await width(), 'zoom in reaches 1.2 times').toBeGreaterThanOrEqual(base * 1.2 - 0.5)
  await page.getByTestId('aes-walk-ks-zoom-reset').click()
  expect(await width()).toBeCloseTo(base, 0)
  while (await zout.isEnabled() && (await width()) > base * 0.85) { await zout.click(); expect(await noSideways(page)).toEqual({ page: false, ks: false }) }
  expect(await width(), 'zoom out reaches 0.85 times').toBeLessThanOrEqual(base * 0.85 + 0.5)
  await page.getByTestId('aes-walk-ks-zoom-reset').click()
  await page.getByTestId('aes-walk-ks-table').hover()
  await page.keyboard.down('Control')
  await page.mouse.wheel(0, -200)
  await page.keyboard.up('Control')
  await expect.poll(width, { message: 'Ctrl and the wheel zoom in' }).toBeGreaterThan(base + 0.5)
})

test('at 1280 wide and wider the round keys sit left of the build panel, below 1280 the panel stacks under them, and nothing scrolls sideways', async ({ page }) => {
  for (const w of [1600, 1280, 1279, 1024]) {
    await page.setViewportSize({ width: w, height: 800 })
    await openPractice(page)
    await toStop(page, KEYS + 1)
    const t = (await page.getByTestId('aes-walk-ks-table').boundingBox())!, b = (await page.getByTestId('aes-walk-ks-build').boundingBox())!
    if (w >= 1280) expect(t.x + t.width, `${w}: the table ends left of the panel`).toBeLessThanOrEqual(b.x + 1)
    else expect(b.y, `${w}: the panel stacks below the table`).toBeGreaterThanOrEqual(t.y + t.height - 1)
    expect(await noSideways(page), `${w}: no sideways scroll`).toEqual({ page: false, ks: false })
  }
})
