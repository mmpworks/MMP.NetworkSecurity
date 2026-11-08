import { expect, test, type Page } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { MIN_RATIO, scanPage, setTheme } from './contrast'
import { holdWithoutDeleteSharing } from './hold-file'
import { startOwnHost, type OwnHost } from './own-host'
import { open } from './walk'

// V3: the Show keys switch is real. The Host redacts at its boundary, so this spec drives the switch and reads the screen against the Host's own answers.
const OUT = path.join(__dirname, '..', 'test-results', 'show-keys-v3')
const shot = async (page: Page, name: string) => { fs.mkdirSync(OUT, { recursive: true }); await page.screenshot({ path: path.join(OUT, `${name}.png`) }) }
const api = (method: string, p: string, body?: unknown) =>
  fetch(`http://127.0.0.1:${host.port}${p}`, { method, headers: { Authorization: `Bearer ${host.token}`, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
const hostOn = async () => ((await (await api('GET', '/api/security/show-keys')).json()) as { on: boolean }).on

test.describe.configure({ mode: 'serial' })

// The own-keys test makes a key for good, and this file flips the Host-wide switch, so it runs on a Host of its own.
let host: OwnHost
test.beforeAll(async () => { host = await startOwnHost() })
test.beforeEach(async () => { await api('PUT', '/api/security/show-keys', { on: true }) })
test.afterAll(async () => { await host.stop() })

async function freePlay(page: Page, lesson: number) {
  await open(page, host)
  await page.getByTestId(`lesson-item-${lesson}`).click()
  await page.getByTestId('mode-free').click()
  await page.getByTestId('free-start').click()
  await page.getByTestId('free-run').click()
  await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 60_000 })
}
const rowText = async (page: Page) => (await page.locator('[data-testid^="secret-row-"]').allInnerTexts()).join('\n')
// The panel shortens long hex to 16 characters, an ellipsis and 8. A value that starts with hex is key bytes; a fingerprint starts with `fp:`.
// Key bytes on screen: a key row that starts with 8 hex bytes, or a match grid with 16 or more cells. A fingerprint fills 8 cells, and the shortest key 16.
const bytesShown = async (page: Page) => (await page.locator('[data-testid^="secret-value-"]').allInnerTexts()).some(t => /^[0-9a-f]{16}/i.test(t.trim()))
  || (await page.locator('[data-testid^=convergence-grid-]').evaluateAll(grids => grids.map(g => g.querySelectorAll('.cell').length))).some(n => n >= 16)
const noBytesOnScreen = async (page: Page) => expect.poll(() => bytesShown(page)).toBe(false)

async function contrast(page: Page, theme: string, screen: string) {
  await page.evaluate(() => Promise.all(document.getAnimations().filter(a => a.effect?.getComputedTiming().iterations !== Infinity).map(a => a.finished.catch(() => null))))
  await page.waitForTimeout(300)
  const s = await scanPage(page)
  console.log(`${theme} ${screen}: ${s.checked} texts checked, ${s.fails.length} failed`)
  expect(s.fails.map(f => `${screen}: ${f.where} "${f.text}" ${f.ratio} (${f.fg} on ${f.bg})`), `${theme} ${screen}`).toEqual([])
}

test('ON: rows show bytes, the Keys in use strip names the key, and the switch reads ON', async ({ page }) => {
  await freePlay(page, 1)
  await expect(page.getByTestId('show-keys-switch')).toBeChecked()
  expect(await rowText(page)).toMatch(/[0-9a-f]{16,}/i)
  await expect(page.getByTestId('keys-in-use')).toBeVisible()
  await expect(page.locator('[data-testid^="key-in-use-"]:not([data-testid^="key-in-use-value-"])').first()).toBeVisible()
  await expect(page.getByTestId('show-keys-off-banner')).toHaveCount(0)
  await shot(page, '01-on')
})

test('OFF: bytes leave the panel at once, fingerprints stay, the banner shows, and ON brings the bytes back', async ({ page }) => {
  await freePlay(page, 1)
  await page.getByTestId('show-keys-switch').uncheck()
  await expect.poll(hostOn).toBe(false)
  await noBytesOnScreen(page)
  expect(await rowText(page)).toMatch(/fp:[0-9a-f]{16}/)
  await expect(page.getByTestId('show-keys-off-banner')).toContainText('Show keys is off, so you see a short fingerprint of each key.')
  await expect(page.getByTestId('key-in-use-lab.aes-key')).toContainText('Built-in key')
  await expect(page.locator('[data-testid^="secret-reveal-"]')).toHaveCount(0)
  await shot(page, '02-off')
  await page.getByTestId('show-keys-switch').check()
  await expect.poll(hostOn).toBe(true)
  await expect.poll(async () => /[0-9a-f]{16,}/i.test(await rowText(page))).toBe(true)
  await expect(page.getByTestId('show-keys-off-banner')).toHaveCount(0)
})

// Own keys: the my-login flow makes token.issuer and device.enrolment, and lesson 10 reads them. Their key.in-use events carry the key.
async function makeLoginKeys() {
  const start = (await (await api('POST', '/api/security/flows/my-login/runs', {})).json()) as { runId: string; step: { stepSeq: number } }
  let seq = start.step.stepSeq
  for (const event of ['next', 'make', 'next', 'check', 'next']) {
    const r = (await (await api('POST', `/api/security/runs/${start.runId}/events`, { event, stepSeq: seq, data: {} })).json()) as { step?: { stepSeq: number } }
    if (!r.step) throw new Error(`event ${event} was refused`)
    seq = r.step.stepSeq
  }
}
const backToBuiltin = async () => { for (const t of ['token.issuer', 'device.enrolment']) await api('PUT', `/api/security/types/${t}/mode`, { mode: 'BuiltIn' }) }
// A built-in type with a training key carries it in key.in-use. Lesson 10 reads pki.root-ca, so its chip shows the key ON and the fingerprint OFF.
test('built-in keys: lesson 10 names pki.root-ca in the strip with its key ON and its fingerprint OFF', async ({ page }) => {
  await backToBuiltin() // an earlier spec file can leave the my-login types in own-key mode
  await freePlay(page, 10)
  const chip = page.getByTestId('key-in-use-pki.root-ca')
  await expect(chip).toContainText('Built-in key')
  await expect(page.getByTestId('key-in-use-value-pki.root-ca')).toHaveText(/[0-9a-f]{16}/i)
  await page.getByTestId('show-keys-switch').uncheck()
  await expect.poll(hostOn).toBe(false)
  await expect(page.getByTestId('key-in-use-value-pki.root-ca')).toHaveText(/^fp:[0-9a-f]{16}$/)
  await shot(page, '07-builtin-key-off')
})

// A built-in type with no long-term key (lab.aes-key makes a fresh key each run) gets a chip with no value.
test('built-in keys with no long-term key: lesson 1 names lab.aes-key with no value', async ({ page }) => {
  await freePlay(page, 1)
  await expect(page.getByTestId('key-in-use-lab.aes-key')).toBeVisible()
  await expect(page.getByTestId('key-in-use-value-lab.aes-key')).toHaveCount(0)
})


test('own keys: lesson 10 names token.issuer in the strip with its key ON and its fingerprint OFF, and the bytes come back', async ({ page }) => {
  await makeLoginKeys()
  try {
    await freePlay(page, 10)
    const chip = page.getByTestId('key-in-use-token.issuer')
    await expect(chip).toBeVisible()
    await expect(chip).toContainText('My test key')
    // The version counts up across runs that share one security folder, so the spec reads it from the Host.
    const rows = ((await (await api('GET', '/api/security')).json()) as { types: { typeId: string; version: number }[] }).types
    const version = rows.find(r => r.typeId === 'token.issuer')?.version ?? 0
    expect(version).toBeGreaterThan(0)
    await expect(chip).toContainText(`version ${version}`)
    await expect(page.getByTestId('key-in-use-value-token.issuer')).toHaveText(/[0-9a-f]{16}/i)
    await shot(page, '05-own-key-on')
    await page.getByTestId('show-keys-switch').uncheck()
    await expect.poll(hostOn).toBe(false)
    await expect(page.getByTestId('key-in-use-value-token.issuer')).toHaveText(/^fp:[0-9a-f]{16}$/)
    await shot(page, '06-own-key-off')
    await page.getByTestId('show-keys-switch').check()
    await expect.poll(hostOn).toBe(true)
    await expect(page.getByTestId('key-in-use-value-token.issuer')).toHaveText(/[0-9a-f]{16}/i)
  } finally { await backToBuiltin() }
})

test('OFF: two sides that hold one key still show a match, from the fingerprints', async ({ page }) => {
  await freePlay(page, 3)
  await page.getByTestId('show-keys-switch').uncheck()
  await expect.poll(hostOn).toBe(false)
  await noBytesOnScreen(page)
  await expect(page.getByTestId('convergence-match').first()).toBeVisible()
  await shot(page, '03-lesson3-off')
})

test('OFF at 1440 x 760: the banner cuts no row of the Message bytes panel', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 760 })
  await freePlay(page, 1)
  await page.locator('[data-testid^=diagram-message-]', { hasText: 'TextGcm1' }).first().click()
  await page.getByTestId('inspector-tab-bytes').click()
  await page.getByTestId('show-keys-switch').uncheck()
  await expect.poll(hostOn).toBe(false)
  await page.waitForTimeout(900)
  const grids = await page.locator('.hex-scroll').evaluateAll(all => all.map(e => ({ shown: e.clientHeight, whole: e.scrollHeight })))
  expect(grids).toHaveLength(2)
  for (const g of grids) expect(g.whole, 'a hex row is cut').toBeLessThanOrEqual(g.shown)
})

// Forced timing, by route.
const eventsRoute = /\/api\/sessions\/[^/]+\/events/

test('a late reply from an ON read cannot put key bytes back after OFF', async ({ page }) => {
  await freePlay(page, 1)
  await page.route(eventsRoute, async route => {
    const reply = await route.fetch()
    const body = await reply.text()
    if (/"hex":"[0-9a-f]{16}/i.test(body)) await page.waitForTimeout(2000)
    await route.fulfill({ response: reply, body })
  })
  const sw = page.getByTestId('show-keys-switch')
  await sw.click()
  await page.waitForTimeout(400)
  await sw.click()
  await page.waitForTimeout(100)
  await sw.click()
  await expect.poll(hostOn).toBe(false)
  await page.waitForTimeout(3500)
  await expect(sw).not.toBeChecked()
  await noBytesOnScreen(page)
  expect(await rowText(page)).toContain('fp:')
})

test('a failed read after OFF leaves no key bytes, and it claims no match', async ({ page }) => {
  await freePlay(page, 1)
  await page.route(eventsRoute, route => route.abort())
  await page.getByTestId('show-keys-switch').click()
  await expect.poll(hostOn).toBe(false)
  await noBytesOnScreen(page)
  await expect(page.locator('[data-testid^="secret-value-"]').first()).toHaveText('Fingerprint not available')
  await expect(page.getByTestId('convergence-match')).toHaveCount(0)
  await expect(page.locator('.converge').first()).not.toContainText('the values differ')
  await page.unroute(eventsRoute)
  await page.getByTestId('show-keys-switch').click()
  await expect.poll(hostOn).toBe(true)
  await expect.poll(async () => /[0-9a-f]{16,}/i.test(await rowText(page))).toBe(true)
})

// Holds the reply of the first PUT only, so the Host takes both flips in order and the first flip's reply lands last.
async function holdFirstPutReply(page: Page) {
  let held = false
  await page.route(/\/api\/security\/show-keys$/, async route => {
    if (route.request().method() !== 'PUT' || held) { await route.continue(); return }
    held = true
    const reply = await route.fetch()
    await page.waitForTimeout(1500)
    await route.fulfill({ response: reply })
  })
}

test('OFF then ON, with the OFF reply landing last: the screen follows the Host, which is ON', async ({ page }) => {
  await freePlay(page, 1)
  await holdFirstPutReply(page)
  const sw = page.getByTestId('show-keys-switch')
  await sw.click()
  await expect.poll(hostOn).toBe(false)
  await sw.click()
  await expect.poll(hostOn).toBe(true)
  await page.waitForTimeout(2500)
  await expect(sw).toBeChecked()
  await expect(page.getByTestId('show-keys-off-banner')).toHaveCount(0)
  await expect.poll(() => bytesShown(page)).toBe(true)
})

test('ON then OFF, with the ON reply landing last: the screen follows the Host, which is OFF', async ({ page }) => {
  await freePlay(page, 1)
  const sw = page.getByTestId('show-keys-switch')
  await sw.click()
  await expect.poll(hostOn).toBe(false)
  await expect(sw).not.toBeChecked()
  await holdFirstPutReply(page)
  await sw.click()
  await expect.poll(hostOn).toBe(true)
  await sw.click()
  await expect.poll(hostOn).toBe(false)
  await page.waitForTimeout(2500)
  await expect(sw).not.toBeChecked()
  await expect(page.getByTestId('show-keys-off-banner')).toBeVisible()
  await noBytesOnScreen(page)
})

test('a flip during a run loses no event', async ({ page }) => {
  await open(page, host)
  await page.route(eventsRoute, async route => {
    const reply = await route.fetch()
    const body = await reply.text()
    await page.waitForTimeout(1500)
    await route.fulfill({ response: reply, body })
  })
  await page.getByTestId('lesson-item-1').click()
  await page.getByTestId('mode-free').click()
  await page.getByTestId('free-start').click()
  await page.waitForTimeout(300)
  await page.getByTestId('show-keys-switch').click()
  await page.waitForTimeout(200)
  await page.getByTestId('free-run').click()
  await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 60_000 })
  await page.waitForTimeout(3000)
  const id = await page.locator('.statusbar').innerText().then(t => /session (?<id>\S+)/.exec(t)?.groups?.id ?? '')
  const held = (await (await api('GET', `/api/sessions/${id}/events`)).json()) as { events?: unknown[] } | unknown[]
  const count = (Array.isArray(held) ? held : held.events ?? []).length
  expect(count).toBeGreaterThan(10)
  await expect(page.getByText(`${count} events`)).toBeVisible()
})

test('a saved trace opens as a replay, and a flip to OFF takes its key bytes off the screen', async ({ page }) => {
  await freePlay(page, 1)
  const id = await page.locator('.statusbar').innerText().then(t => /session (?<id>\S+)/.exec(t)?.groups?.id ?? '')
  const file = await new Promise<string>((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${host.port}/ws?token=${host.token}`)
    ws.onopen = () => ws.send(JSON.stringify({ type: 'session.save', sessionId: id }))
    ws.onmessage = m => { const f = JSON.parse(String(m.data)); if (f.type === 'session.saved') { ws.close(); resolve(String(f.sessionFile)) } }
    ws.onerror = () => reject(new Error('the socket failed'))
  })
  await page.getByTestId('open-trace-path').fill(file)
  await page.getByTestId('open-trace').click()
  await expect(page.getByTestId('replay-chip')).toBeVisible()
  await expect.poll(async () => /[0-9a-f]{16,}/i.test(await rowText(page))).toBe(true)
  await page.getByTestId('show-keys-switch').click()
  await expect.poll(hostOn).toBe(false)
  await noBytesOnScreen(page)
})

test('OFF: the key log is refused by name', async ({ page }) => {
  await freePlay(page, 1)
  const id = await page.locator('.statusbar').innerText().then(t => /session (?<id>\S+)/.exec(t)?.groups?.id ?? '')
  expect(id).not.toBe('')
  await page.getByTestId('show-keys-switch').uncheck()
  await expect.poll(hostOn).toBe(false)
  const r = await api('GET', `/api/sessions/${id}/keylog`)
  expect(r.status).toBe(409)
  expect(((await r.json()) as { code: string }).code).toBe('KEYS_HIDDEN')
})

for (const theme of ['light', 'dark'] as const) {
  test(`every Show keys state reads at ${MIN_RATIO} to 1 in the ${theme} theme`, async ({ page }) => {
    test.setTimeout(240_000)
    await freePlay(page, 1)
    await setTheme(page, theme)
    await contrast(page, theme, 'lesson 1, keys shown, strip')
    await page.getByTestId('show-keys-switch').uncheck()
    await expect.poll(hostOn).toBe(false)
    await expect(page.getByTestId('show-keys-off-banner')).toBeVisible()
    await contrast(page, theme, 'lesson 1, keys hidden, banner, strip')
    for (const n of [3, 6]) {
      await page.getByTestId(`lesson-item-${n}`).click()
      await page.getByTestId('free-start').click()
      await page.getByTestId('free-run').click()
      await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 60_000 })
      await contrast(page, theme, `lesson ${n}, keys hidden`)
      for (const tab of await page.locator('[data-testid^=inspector-tab-]').all()) { await tab.click(); await contrast(page, theme, `lesson ${n}, keys hidden, tab ${await tab.getAttribute('data-testid')}`) }
    }
    await shot(page, `04-off-${theme}`)
  })
}

// Binary hover with Show keys OFF: a tip reads only what its cell shows, so it can never show a key byte the cells hide.
test('OFF: the binary hover in What each side knows and in Message bytes shows no key bytes', async ({ page }) => {
  await freePlay(page, 1)
  await page.locator('[data-testid^=diagram-message-]', { hasText: 'TextGcm1' }).first().click()
  const grid = page.locator('[data-testid^=convergence-grid-]').first().locator('.cell')
  const key = (await grid.allInnerTexts()).join('')
  expect(key, 'the key bytes while ON').toMatch(/^[0-9a-f]{32}$/)
  await page.getByTestId('show-keys-switch').uncheck()
  await expect.poll(hostOn).toBe(false)
  await noBytesOnScreen(page)
  const tip = page.getByTestId('binary-tip')
  const cells = [page.locator('[data-testid^=convergence-grid-] .cell'), page.locator('[data-testid^=inspector-byte-]')]
  const tips: string[] = []
  for (const set of cells) {
    const n = Math.min(await set.count(), 32)
    for (let i = 0; i < n; i++) {
      const cell = set.nth(i)
      await cell.hover()
      const shown = (await cell.textContent())!.trim()
      if (/^[0-9a-f]{2}$/i.test(shown)) {
        // The whole tip is pinned to its cell: its byte and that byte's 8 bits, and nothing more.
        await expect(tip).toHaveText(new RegExp(`^${shown.toLowerCase()} = [01]{4} [01]{4}$`))
        tips.push((await tip.innerText()).split(' = ')[0])
      } else await expect(tip).toHaveCount(0)
    }
  }
  expect(tips.length, 'tips read').toBeGreaterThan(16)
  const joined = tips.join('')
  for (let i = 0; i + 8 <= key.length; i += 2) expect(joined.includes(key.slice(i, i + 8)), `4 key bytes from offset ${i / 2} in the tips`).toBe(false)
  await page.mouse.move(5, 300)
  await page.locator('[data-testid^=convergence-grid-] .cell').first().hover()
  await shot(page, '08-off-binary-hover')
})

// Issue #292: with modes.json held, turning Show keys off still takes effect, but the Host cannot save it yet. The Security panel says
// "not saved yet" until the Host's background retry saves it, then the note goes.
test('a Show keys off the Host could not save shows "not saved yet" until the retry saves it', async ({ page }) => {
  await open(page, host)
  await page.getByTestId('security-setup-button').click()
  await expect(page.getByTestId('sec-page')).toBeVisible()
  await expect(page.getByTestId('sec-show-keys-unsaved')).toHaveCount(0)
  const hold = await holdWithoutDeleteSharing(path.join(host.securityDir, 'modes.json'))
  try {
    await page.getByTestId('sec-show-keys-switch').click()
    await expect(page.getByTestId('sec-show-keys-switch')).not.toBeChecked()
    await expect(page.getByTestId('sec-show-keys-unsaved')).toBeVisible()
    await expect(page.getByTestId('sec-show-keys-unsaved')).toHaveText('Show keys is off, but the choice is not saved yet. The course keeps trying.')
    expect(await hostOn()).toBe(false)
    await shot(page, '09-not-saved-yet')
  } finally { await hold.release() }
  await expect(page.getByTestId('sec-show-keys-unsaved')).toHaveCount(0, { timeout: 10_000 })
  await expect(page.getByTestId('sec-show-keys-switch')).not.toBeChecked()
})
