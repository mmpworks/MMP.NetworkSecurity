import { expect, test, type Page } from '@playwright/test'
import { scanPage, setTheme } from './contrast'
import { PORTS } from './ports'
import { TOKEN, open } from './walk'

// The Diffie-Hellman walk (slice P7; docs/sections-plan.md section 5; Steve's paint chips from mock v28's DH tab). Every number is the
// engine's (R5): each check compares the screen with GET /api/walk/dh. Test ids follow Echo's #267.

const CHIPS: { name: string; colour: string | null; letter: string | null }[] = [
  { name: 'client-private', colour: 'red', letter: 'a' }, { name: 'server-private', colour: 'blue', letter: 'b' },
  { name: 'g', colour: 'yellow', letter: 'g' }, { name: 'client-public', colour: 'orange', letter: 'A' },
  { name: 'server-public', colour: 'green', letter: 'B' }, { name: 'client-shared', colour: 'brown', letter: 's' },
  { name: 'server-shared', colour: 'brown', letter: 's' }, { name: 'n', colour: null, letter: null },
]
const FROM = [{ name: 'from-client', colour: 'orange', letter: 'A' }, { name: 'from-server', colour: 'green', letter: 'B' }]

async function reply(group: 'small' | 'group14' = 'small'): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${PORTS.host}/api/walk/dh?group=${group}`, { headers: { Authorization: `Bearer ${TOKEN}` } })
  expect(r.status).toBe(200)
  return r.json()
}
const valuesOf = (w: any): Record<string, { hex: string; dec: string }> => ({
  'client-private': w.client.private, 'server-private': w.server.private, g: w.generator, 'client-public': w.client.public.result,
  'server-public': w.server.public.result, 'client-shared': w.client.shared.result, 'server-shared': w.server.shared.result, n: w.prime,
})
const flat = async (page: Page, id: string) => ((await page.getByTestId(id).textContent()) ?? '').replace(/\s+/g, '')
const shows = (t: string, v: { hex: string; dec: string }) => t === v.dec || t.toLowerCase() === v.hex.toLowerCase() || t.toLowerCase() === `0x${v.hex.toLowerCase()}`

async function openDh(page: Page) {
  await open(page)
  await page.getByTestId('section-techniques').click()
  await page.getByTestId('walk-item-dh').click()
  await expect(page.getByTestId('walk-root').getByTestId('dh-walk-panel')).toBeVisible()
}

test('each value shows the engine\'s number and its paint chip, n has none, and both sides reach one secret', async ({ page }) => {
  const want = valuesOf(await reply())
  await openDh(page)
  for (const v of CHIPS) {
    expect(shows(await flat(page, `dh-value-${v.name}-number`), want[v.name]), `${v.name} shows ${want[v.name].dec}`).toBe(true)
    if (v.colour === null) { await expect(page.getByTestId(`dh-chip-${v.name}`)).toHaveCount(0); continue }
    await expect(page.getByTestId(`dh-chip-${v.name}`)).toHaveAttribute('data-chip', v.colour)
  }
  for (const f of FROM) await expect(page.getByTestId(`dh-chip-${f.name}`)).toHaveAttribute('data-chip', f.colour)
  expect(want['client-shared'].dec).toBe(want['server-shared'].dec)
  // The walk is built, so its rail line no longer says it comes later.
  await expect(page.getByTestId('walk-item-dh')).not.toContainText('later update')
})

test('each chip names its colour for screen readers and shows its DH letter, and the legend pairs colour and letter', async ({ page }) => {
  await openDh(page)
  for (const c of [...CHIPS.filter(v => v.colour), ...FROM] as { name: string; colour: string; letter: string }[]) {
    const chip = page.getByTestId(`dh-chip-${c.name}`)
    expect(((await chip.getAttribute('aria-label')) ?? '').toLowerCase()).toContain(c.colour)
    await expect(chip).toHaveAttribute('data-letter', c.letter)
    expect(((await chip.innerText()) ?? '').trim()).toBe(c.letter)
  }
  const legend = ((await page.getByTestId('dh-chip-legend').innerText()) ?? '').toLowerCase()
  for (const colour of ['red', 'blue', 'yellow', 'orange', 'green', 'brown']) expect(legend).toContain(colour)
})

test('the real-size note reads realExponentBits from the reply, and names this walk\'s own exponent size', async ({ page }) => {
  const w = await reply()
  const planted = Number(w.realExponentBits) === 333 ? 334 : 333
  await page.route(/\/api\/walk\/dh(\?|$)/, async route => { const r = await route.fetch(); route.fulfill({ response: r, json: { ...(await r.json()), realExponentBits: planted } }) })
  await openDh(page)
  await expect(page.getByTestId('dh-real-size-bits')).toHaveText(String(planted))
  // The small walk's exponents are one byte each (153 and 197), so the note must not claim the group 14 walk's 32 bits.
  await expect(page.getByTestId('dh-real-size')).toContainText(`${(w.client.private.hex.length / 2) * 8}-bit practice exponent`)
})

/** Sets Show keys through the Host, so the restore in `finally` still runs when the page has closed. The Host keeps the toggle for later specs. */
const showKeys = (on: boolean) => fetch(`http://127.0.0.1:${PORTS.host}/api/security/show-keys`, {
  method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}`, Origin: 'http://localhost:5173' }, body: JSON.stringify({ on }),
})

test('with Show keys off the walk still shows its practice numbers and chips', async ({ page }) => {
  expect((await showKeys(false)).ok, 'PUT show-keys off').toBe(true)
  try {
    const want = valuesOf(await reply())
    await openDh(page)
    for (const name of ['client-private', 'server-private', 'client-shared']) {
      expect(shows(await flat(page, `dh-value-${name}-number`), want[name])).toBe(true)
      await expect(page.getByTestId(`dh-chip-${name}`)).toBeVisible()
    }
  } finally {
    await showKeys(true)
  }
})

test('stepping shows the exchange in order, and each power shows the engine\'s square-and-multiply rows', async ({ page }) => {
  const w = await reply()
  await openDh(page)
  await page.getByTestId('dh-next').click()
  // Step 0: only n and g, which both sides agree on in public.
  await expect(page.getByTestId('dh-value-n')).toBeVisible()
  await expect(page.getByTestId('dh-value-client-public')).toHaveCount(0)
  for (let i = 0; i < 3; i++) await page.getByTestId('dh-next').click()
  // Step 3: the client works g to the power a. The rows are the engine's, one per bit of a, and the last row is the public value.
  await expect(page.getByTestId('dh-caption')).toContainText(`${w.generator.dec} to the power ${w.client.private.dec}, mod ${w.prime.dec} = ${w.client.public.result.dec}`)
  const rows = page.locator('[data-testid^="dh-row-"]')
  await expect(rows).toHaveCount(w.client.public.rows.length)
  const last = w.client.public.rows[w.client.public.rows.length - 1]
  expect(await flat(page, `dh-row-${w.client.public.rows.length - 1}`)).toContain((last.afterMultiply ?? last.afterSquare).dec)
  await page.getByTestId('dh-all').click()
  await expect(page.getByTestId('dh-value-server-shared')).toBeVisible()
})

test('group 14 shows the real group\'s numbers from the engine', async ({ page }) => {
  const w = await reply('group14')
  await openDh(page)
  await page.getByTestId('dh-group-group14').click()
  for (const name of ['client-public', 'client-shared', 'n']) expect(shows(await flat(page, `dh-value-${name}-number`), valuesOf(w)[name]), name).toBe(true)
  await expect(page.getByTestId('dh-real-size')).toContainText('32-bit practice exponent')
})

test('on group 14 the caption shows a long number in the short form the step rows use', async ({ page }) => {
  const w = await reply('group14')
  const shortOf = (hex: string) => `${hex.slice(0, 16)}…${hex.slice(-8)}`.toLowerCase()
  await openDh(page)
  await page.getByTestId('dh-group-group14').click()
  const caption = page.getByTestId('dh-caption')
  const secret = w.client.shared.result.hex as string
  await expect(caption).toContainText(secret.slice(-8), { ignoreCase: true })
  let text = ((await caption.textContent()) ?? '').toLowerCase()
  expect(text, 'summary caption').toContain(shortOf(secret))
  expect(text, 'summary caption').not.toContain(secret.toLowerCase())
  for (let i = 0; i < 4; i++) await page.getByTestId('dh-next').click()
  const A = w.client.public.result.hex as string
  await expect(caption).toContainText(A.slice(-8), { ignoreCase: true })
  text = ((await caption.textContent()) ?? '').toLowerCase()
  expect(text, 'step caption').toContain(shortOf(A))
  expect(text, 'step caption').not.toContain(A.toLowerCase())
})

for (const theme of ['light', 'dark'] as const) {
  test(`every text and chip letter reads at 4.5 to 1 in the ${theme} theme`, async ({ page }) => {
    await openDh(page)
    await setTheme(page, theme)
    await page.waitForTimeout(300)
    const s = await scanPage(page)
    expect(s.checked).toBeGreaterThan(40)
    expect(s.fails, JSON.stringify(s.fails.slice(0, 5))).toEqual([])
  })
}

for (const size of [{ width: 1280, height: 640 }, { width: 1984, height: 1030 }]) {
  test(`at ${size.width} x ${size.height} the walk does not scroll sideways, even on group 14`, async ({ page }) => {
    await page.setViewportSize(size)
    await openDh(page)
    for (const g of ['small', 'group14']) {
      await page.getByTestId(`dh-group-${g}`).click()
      await expect(page.getByTestId('dh-value-n-number')).not.toHaveText('')
      const wide = await page.evaluate(() => { const ws = document.querySelector('[data-testid="workspace"]') as HTMLElement; const b = ws.scrollLeft; ws.scrollLeft = 500; const m = ws.scrollLeft !== b; ws.scrollLeft = b; return m || document.documentElement.scrollWidth > document.documentElement.clientWidth })
      expect(wide, `${g} at ${size.width}`).toBe(false)
    }
  })
}
