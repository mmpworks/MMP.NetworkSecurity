import { expect, test, type Page } from '@playwright/test'
import { scanPage, setTheme } from './contrast'
import { PORTS } from './ports'
import { TOKEN, open } from './walk'

// The Handshake key schedule walks (docs/sections-plan.md section 4, slices P4 and P4b; R8). Each screen shows one engine reply and
// computes nothing (R5), so each check compares the screen with the Host's own reply.

async function reply(route: string): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${PORTS.host}${route}`, { headers: { Authorization: `Bearer ${TOKEN}` } })
  expect(r.status, `GET ${route}`).toBe(200)
  return r.json()
}

async function openWalk(page: Page, item: 'tls13' | 'tls11') {
  await open(page)
  await page.getByTestId('section-handshake').click()
  await page.getByTestId(`walk-item-${item}`).click()
  await expect(page.getByTestId('walk-root').getByTestId(`${item}-schedule-panel`)).toBeVisible()
}

/** Leaves Show keys on, because the Host keeps the toggle for every later spec. */
async function keysOn(page: Page) {
  const sw = page.getByTestId('show-keys-switch')
  if (!(await sw.isChecked())) await sw.click()
  await expect(sw).toBeChecked()
}

const flat = async (page: Page, id: string) => ((await page.getByTestId(id).textContent()) ?? '').replace(/\s+/g, '')

async function tls13Matches(page: Page, steps: any[]) {
  await expect(page.locator('[data-testid^="tls13-step-"][data-name]')).toHaveCount(steps.length)
  for (let i = 0; i < steps.length; i++) {
    await expect(page.getByTestId(`tls13-step-${i}`)).toHaveAttribute('data-name', steps[i].name)
    expect(await flat(page, `tls13-step-output-${i}`), `step ${i} output`).toBe(steps[i].output)
    if (steps[i].label) await expect(page.getByTestId(`tls13-step-label-${i}`)).toContainText(`"${steps[i].label}"`)
    // RFC 8446's Derive-Secret takes the messages and hashes them itself, so the screen shows the expanded form with the hash.
    if (steps[i].kind === 'DeriveSecret') await expect(page.getByTestId(`tls13-step-label-${i}`)).toContainText(`HKDF-Expand-Label(secret, "${steps[i].label}", transcript hash, ${steps[i].output.length / 2})`)
  }
}

const TLS11: [string, (w: any) => string][] = [
  ['tls11-premaster', w => w.premaster], ['tls11-master', w => w.masterSecret.value],
  ['tls11-client-mac-key', w => w.keyBlock.clientMacKey], ['tls11-server-mac-key', w => w.keyBlock.serverMacKey],
  ['tls11-client-key', w => w.keyBlock.clientKey], ['tls11-server-key', w => w.keyBlock.serverKey],
]

test('the TLS 1.3 walk shows every engine step with its formula and output, and names RFC 8448\'s test key', async ({ page }) => {
  const w = await reply('/api/walk/tls13/schedule')
  await openWalk(page, 'tls13')
  await tls13Matches(page, w.steps)
  await expect(page.getByTestId('tls13-key-source')).toHaveAttribute('data-key-source', 'rfc8448')
  await expect(page.getByTestId('tls13-key-source')).toContainText("RFC 8448's published test key")
})

test('the TLS 1.1 walk shows pre-master, master and the 4 keys in that order, the key log line, and names the public training key', async ({ page }) => {
  const w = await reply('/api/walk/tls11/schedule')
  await openWalk(page, 'tls11')
  for (const [id, pick] of TLS11) expect(await flat(page, id), id).toBe(pick(w))
  const ys = await Promise.all(TLS11.map(async ([id]) => (await page.getByTestId(id).boundingBox())!.y))
  expect([...ys].sort((a, b) => a - b), 'pre-master, master, then the 4 keys, top to bottom').toEqual(ys)
  expect(await flat(page, 'tls11-key-log')).toBe(String(w.keyLogLine).replace(/\s+/g, ''))
  // The version reads as the 2 bytes the pre-master starts with.
  expect(await flat(page, 'tls11-premaster-version'), 'the version is the pre-master\'s first 2 bytes').toContain(String(w.premaster).slice(0, 4))
  await expect(page.getByTestId('tls11-key-source')).toHaveAttribute('data-key-source', 'training')
  await expect(page.getByTestId('tls11-key-source')).toContainText('public in the source')
})

test('with Show keys off, both walks stay open and show every value', async ({ page }) => {
  await open(page)
  const sw = page.getByTestId('show-keys-switch')
  if (await sw.isChecked()) await sw.click()
  await expect(sw).not.toBeChecked()
  try {
    const w13 = await reply('/api/walk/tls13/schedule')
    const w11 = await reply('/api/walk/tls11/schedule')
    await page.getByTestId('section-handshake').click()
    await page.getByTestId('walk-item-tls13').click()
    await tls13Matches(page, w13.steps)
    await page.getByTestId('walk-item-tls11').click()
    for (const [id, pick] of TLS11) expect(await flat(page, id), id).toBe(pick(w11))
  } finally {
    await keysOn(page)
  }
})

test('a failed walk route shows its route and the Host\'s code, and Try again loads the walk', async ({ page }) => {
  let fail = true
  await page.route('**/api/walk/tls11/schedule', r => (fail ? r.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ code: 'TLS11_WALK_DIVERGED' }) }) : r.continue()))
  await openWalk(page, 'tls11')
  await expect(page.getByTestId('tls11-schedule-error')).toContainText('/api/walk/tls11/schedule failed: TLS11_WALK_DIVERGED')
  fail = false
  await page.getByTestId('tls11-schedule-error').getByRole('button', { name: 'Try again' }).click()
  await expect(page.getByTestId('tls11-premaster')).toBeVisible()
})

// The contrast sweep (contrast-sweep.spec.ts) visits the lesson screens only, so these 2 walks carry their own scan, in both themes.
for (const theme of ['light', 'dark'] as const) {
  test(`every text on both walks reads at 4.5 to 1 in the ${theme} theme`, async ({ page }) => {
    for (const item of ['tls13', 'tls11'] as const) {
      await openWalk(page, item)
      await setTheme(page, theme)
      await expect(page.locator(`[data-testid="${item}-schedule-panel"] .hex.out`).first()).toBeVisible()
      await page.waitForTimeout(300)
      const s = await scanPage(page)
      expect(s.checked, `${item}: the scan read the walk's texts`).toBeGreaterThan(30)
      expect(s.fails, `${item}: ${JSON.stringify(s.fails.slice(0, 5))}`).toEqual([])
    }
  })
}

// The house layout rule: no screen scrolls sideways at 1280 or at 1984 (layout-sweep.spec.ts check 9 tests the lesson panes).
for (const size of [{ width: 1280, height: 640 }, { width: 1984, height: 1030 }]) {
  test(`at ${size.width} x ${size.height} neither walk scrolls sideways`, async ({ page }) => {
    await page.setViewportSize(size)
    for (const item of ['tls13', 'tls11'] as const) {
      await openWalk(page, item)
      await expect(page.locator(`[data-testid="${item}-schedule-panel"] .hex.out`).first()).toBeVisible()
      const wide = await page.evaluate(() => {
        const ws = document.querySelector('[data-testid="workspace"]') as HTMLElement
        const before = ws.scrollLeft
        ws.scrollLeft = 500
        const moved = ws.scrollLeft !== before
        ws.scrollLeft = before
        return { moved, page: document.documentElement.scrollWidth > document.documentElement.clientWidth }
      })
      expect(wide, `${item} at ${size.width}`).toEqual({ moved: false, page: false })
    }
  })
}
