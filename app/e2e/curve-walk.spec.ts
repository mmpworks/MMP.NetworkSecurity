import { expect, test, type Locator, type Page } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { scanPage, setTheme, settle } from './contrast'
import { PORTS } from './ports'
import { TOKEN, open } from './walk'

// The elliptic-curve walks (slices P8a and P8; docs/sections-plan.md R7, the order of video 4Tfmwxr0I34). Every number is the engine's (R5):
// each check compares the screen with GET /api/walk/real-curve, /api/walk/toy-curve, /api/walk/toy-curve/add and /api/walk/x25519.
// Test ids follow Echo's #278.

type Pt = { x: number; y: number } | null
const pt = (o: any): Pt => (o && o.infinity ? null : { x: Number(o?.x), y: Number(o?.y) })
const same = (a: Pt, b: Pt) => (a === null || b === null ? a === b : a.x === b.x && a.y === b.y)
const close = (a: Pt, b: Pt) => a !== null && b !== null && Math.abs(a.x - b.x) < 1e-9 && Math.abs(a.y - b.y) < 1e-9
const dotId = (p: Pt) => (p === null ? 'curve-point-O' : `curve-point-${p.x}-${p.y}`)
async function shownPt(el: Locator): Promise<Pt> {
  if ((await el.getAttribute('data-point')) === 'O') return null
  return { x: Number(await el.getAttribute('data-x')), y: Number(await el.getAttribute('data-y')) }
}
const text = async (el: Locator) => ((await el.textContent()) ?? '').trim()

async function reply(route: string): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${PORTS.host}${route}`, { headers: { Authorization: `Bearer ${TOKEN}` } })
  expect(r.status, route).toBe(200)
  return r.json()
}
async function openItem(page: Page, item: string, root: string) {
  await open(page)
  await page.getByTestId('section-techniques').click()
  await page.getByTestId(`walk-item-${item}`).click()
  await expect(page.getByTestId('walk-root').getByTestId(root)).toBeVisible()
}
const openCurve = (page: Page) => openItem(page, 'curve', 'curve-walk-panel')

test('the rail holds "Elliptic curves" above X25519, and both walks have a status line', async ({ page }) => {
  await open(page)
  await page.getByTestId('section-techniques').click()
  const titles = await page.getByTestId('section-rail').locator('[data-testid^=walk-item-] .rail-title').allTextContents()
  expect(titles.indexOf('Elliptic curves'), titles.join(', ')).toBe(titles.indexOf('X25519') - 1)
  for (const item of ['curve', 'x25519']) await expect(page.getByTestId(`walk-item-${item}`)).not.toContainText('later update')
})

test('the GF(17) scatter shows the engine\'s 18 points as dots, plus O', async ({ page }) => {
  const toy = await reply('/api/walk/toy-curve')
  await openCurve(page)
  const scatter = page.getByTestId('curve-scatter')
  expect(await scatter.locator('[data-testid^="curve-point-"][data-x]').count()).toBe(18)
  for (const p of toy.points.map(pt)) expect(same(await shownPt(scatter.getByTestId(dotId(p))), p)).toBe(true)
  await expect(page.getByTestId('curve-point-O')).toBeVisible()
})

test('the real curve shows the engine\'s chord, R\' and R, and each offered pick, the tangent included', async ({ page }) => {
  const real = await reply('/api/walk/real-curve')
  await openCurve(page)
  const keys = [['curve-real-point-p', 'p'], ['curve-real-point-q', 'q'], ['curve-real-point-r-prime', 'rPrime'], ['curve-real-point-r', 'r']]
  for (const [id, key] of keys) expect(close(await shownPt(page.getByTestId(id)), pt(real.chord[key])), key).toBe(true)
  await expect(page.getByTestId('curve-real-chord')).toBeVisible()
  await expect(page.getByTestId('curve-real-reflect')).toBeVisible()
  for (let s = 0; s < real.samples.length; s++) {
    await page.getByTestId(`curve-real-sample-${s}`).click()
    for (const [id, key] of keys) expect(close(await shownPt(page.getByTestId(id)), pt(real.samples[s][key])), `sample ${s} ${key}`).toBe(true)
    if (real.samples[s].kind === 'tangent') await expect(page.getByTestId('curve-real-tangent')).toBeVisible()
  }
})

test('picking 2 dots shows the engine\'s sum and slope, a double shows the tangent, and O adds nothing', async ({ page }) => {
  const toy = await reply('/api/walk/toy-curve')
  const list: Pt[] = [...toy.points.map(pt), null]
  await openCurve(page)
  for (const [i, j] of [[1, 7], [4, 4], [2, 18]]) {
    const want = await reply(`/api/walk/toy-curve/add?p=${i}&q=${j}`)
    await page.getByTestId(dotId(list[i])).click()
    await expect(page.getByTestId(dotId(list[i]))).toHaveAttribute('data-picked', 'P')
    await page.getByTestId(dotId(list[j])).click()
    if (i !== j) await expect(page.getByTestId(dotId(list[j]))).toHaveAttribute('data-picked', 'Q')
    await expect(page.getByTestId('curve-point-r')).toBeVisible()
    expect(same(await shownPt(page.getByTestId('curve-point-r')), pt(want.step.result)), `${i} + ${j}`).toBe(true)
    if (i === j) await expect(page.getByTestId('curve-tangent')).toBeVisible()
    if (want.step.lambda === null) continue
    const slope = page.getByTestId('curve-slope')
    for (const [id, key] of [['curve-slope-num', 'numerator'], ['curve-slope-den', 'denominator'], ['curve-slope-lambda', 'lambda']])
      expect(await text(slope.getByTestId(id)), key).toBe(String(want.step[key]))
    expect(await text(slope.getByTestId('curve-slope-inverse'))).toContain(String(want.step.inverse.value))
    expect(await slope.locator('[data-testid^="curve-slope-euclid-"]').count(), 'one row per extended Euclid step').toBe(want.step.inverse.rows.length)
  }
})

test('k*G hops land on the engine\'s points, the 19th on O, and double-and-add walks k = 13\'s bits', async ({ page }) => {
  const toy = await reply('/api/walk/toy-curve')
  await openCurve(page)
  expect(await text(page.getByTestId('curve-hop-count'))).toContain(String(toy.curve.order))
  for (let i = 0; i < toy.hops.length; i++) expect(same(await shownPt(page.getByTestId(`curve-hop-${i}`)), pt(toy.hops[i].point)), `hop ${i}`).toBe(true)
  expect(await shownPt(page.getByTestId('curve-hop-18'))).toBeNull()
  for (let i = 0; i < toy.doubleAndAdd.length; i++) {
    const row = toy.doubleAndAdd[i]
    expect(await text(page.getByTestId(`curve-dna-bit-${i}`))).toBe(row.isOne ? '1' : '0')
    expect(same(await shownPt(page.getByTestId(`curve-dna-point-${i}`)), pt(row.after)), `row ${i}`).toBe(true)
  }
  for (let i = 0; i < toy.ladder.length; i++) expect(same(await shownPt(page.getByTestId(`curve-ladder-r0-${i}`)), pt(toy.ladder[i].r0)), `ladder ${i}`).toBe(true)
})

test('playing the hops moves a marker from dot to dot, and it ends on O', async ({ page }) => {
  const toy = await reply('/api/walk/toy-curve')
  await openCurve(page)
  await page.getByTestId('curve-hops-next').click()
  const at = page.getByTestId('curve-hop-marker')
  expect(same(await shownPt(at), pt(toy.hops[0].point))).toBe(true)
  await page.getByTestId('curve-hops-next').click()
  expect(same(await shownPt(at), pt(toy.hops[1].point))).toBe(true)
  await expect(page.getByTestId('curve-hop-1')).toHaveAttribute('aria-current', 'true')
  await page.getByTestId('curve-hops-all').click()
  expect(await shownPt(at)).toBeNull()
})

test('the nonce-reuse panel shows the engine\'s 2 signatures and the key it recovers', async ({ page }) => {
  const ec = (await reply('/api/walk/toy-curve')).ecdsa
  await openCurve(page)
  const panel = page.getByTestId('curve-reuse-panel')
  const fields: [string, unknown][] = [['d', ec.signerPrivate], ['k', ec.first.nonce], ['r', ec.first.r], ['s1', ec.first.s], ['s2', ec.second.s],
    ['z1', ec.first.z], ['z2', ec.second.z], ['recovered-d', ec.recovery.privateKey]]
  for (const [id, value] of fields) expect(await text(panel.getByTestId(`curve-reuse-${id}`)), id).toBe(String(value))
})

test('the X25519 walk shows one ladder row per bit with its swap, and ends on RFC 7748\'s value', async ({ page }) => {
  const x = await reply('/api/walk/x25519?step=alice-public')
  const vec = fs.readFileSync(path.join(__dirname, '..', '..', 'acceptance', 'vectors', 'x25519-rfc7748.nsv'), 'utf8')
  const want = (vec.split(/^\[x25519-dh\]/m)[1] ?? '').match(/^a_pub\s*=\s*(?<hex>[0-9a-f]+)/m)!.groups!.hex
  await openItem(page, 'x25519', 'x25519-walk-panel')
  expect(await page.locator('[data-testid^="x25519-row-"]').count()).toBe(255)
  for (const i of [0, 1, 100, 254]) {
    expect(await text(page.getByTestId(`x25519-bit-${i}`))).toBe(x.rows[i].isOne ? '1' : '0')
    expect(await page.getByTestId(`x25519-swap-${i}`).getAttribute('data-swap')).toBe(String(x.rows[i].swap))
  }
  expect(((await page.getByTestId('x25519-result').textContent()) ?? '').replace(/\s+/g, '').toLowerCase()).toBe(want)
  await page.getByTestId('x25519-next').click()
  await page.getByTestId('x25519-next').click()
  await expect(page.getByTestId('x25519-row-1')).toHaveAttribute('aria-current', 'true')
  expect(await text(page.getByTestId('x25519-now-x2'))).toBe(x.rows[1].x2)
})

test('with Show keys off both walks still show their public teaching numbers', async ({ page }) => {
  const ec = (await reply('/api/walk/toy-curve')).ecdsa
  await open(page)
  const sw = page.getByTestId('show-keys-switch')
  if (await sw.isChecked()) await sw.click()
  await expect(sw).not.toBeChecked()
  try {
    await page.getByTestId('section-techniques').click()
    await page.getByTestId('walk-item-curve').click()
    await expect(page.getByTestId('curve-reuse-recovered-d')).toHaveText(String(ec.recovery.privateKey))
    await page.getByTestId('walk-item-x25519').click()
    await expect(page.getByTestId('x25519-result')).not.toHaveText('')
  } finally {
    // The Host keeps the toggle for every later spec, so it goes back on.
    await sw.click()
    await expect(sw).toBeChecked()
  }
})

for (const theme of ['light', 'dark'] as const) {
  for (const item of [['curve', 'curve-walk-panel'], ['x25519', 'x25519-walk-panel']]) {
    test(`the ${item[0]} walk reads at 4.5 to 1 in the ${theme} theme`, async ({ page }) => {
      await openItem(page, item[0], item[1])
      await setTheme(page, theme)
      await settle(page)
      const s = await scanPage(page)
      expect(s.checked).toBeGreaterThan(30)
      expect(s.fails, JSON.stringify(s.fails.slice(0, 5))).toEqual([])
    })
  }
}

for (const size of [{ width: 1280, height: 640 }, { width: 1984, height: 1030 }]) {
  test(`at ${size.width} x ${size.height} neither walk scrolls sideways`, async ({ page }) => {
    await page.setViewportSize(size)
    for (const item of [['curve', 'curve-walk-panel'], ['x25519', 'x25519-walk-panel']]) {
      await openItem(page, item[0], item[1])
      const wide = await page.evaluate(() => { const ws = document.querySelector('[data-testid="workspace"]') as HTMLElement; const b = ws.scrollLeft; ws.scrollLeft = 500; const m = ws.scrollLeft !== b; ws.scrollLeft = b; return m || document.documentElement.scrollWidth > document.documentElement.clientWidth })
      expect(wide, item[0]).toBe(false)
    }
  })
}
