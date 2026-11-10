import { expect, test, type Locator, type Page } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { NotRun, hostGet, openApp, requireLive, controlMissing } from './support';

/**
 * R7, the elliptic-curve walk screens (docs/sections-plan.md R7 and section 4, slices P8a and P8). They teach in the order of video
 * 4Tfmwxr0I34: the chord rule on the real curve (P, Q, the third point R', the reflection R), tangent doubling, then the same curve over
 * GF(17) as a scatter of 18 points plus O, k*G as hops through the dots with order 19, double-and-add on k = 13's bits, and ECDSA on the toy
 * curve, where a reused nonce gives away the key. The X25519 screen shows the Montgomery ladder, one row per bit.
 * Every number comes from the engine (R5): /api/walk/real-curve, /api/walk/toy-curve, /api/walk/toy-curve/add and /api/walk/x25519. These
 * clauses read the same replies and compare. The X25519 result is also checked against RFC 7748 section 6.1 in the vector file.
 * Test ids (Nancy's P8a and P8 plan, 2026-11-08; the rail item walk-item-curve, "Elliptic curves", above X25519, is the lead's call): the
 * toy walk is curve-walk-panel inside walk-root, its scatter curve-scatter, each point curve-point-{x}-{y} with data-x and data-y, and O
 * curve-point-O. A pick carries data-picked P or Q. The chord, R', R and the reflection are curve-chord, curve-point-r-prime, curve-point-r,
 * curve-reflect, and the same ids with the prefix curve-real- on the real-curve picture. Doubling shows curve-tangent, and the slope panel is
 * curve-slope with curve-slope-num, -den, -inverse and -lambda. Hops are curve-hop-{i} (the last has data-point="O") and curve-hop-count.
 * Double-and-add rows are curve-dna-row-{i} with curve-dna-bit-{i} and curve-dna-point-{i}. The nonce-reuse panel is curve-reuse-panel with
 * curve-reuse-d, -k, -r, -s1, -s2, -z1, -z2 and curve-reuse-recovered-d. X25519 is x25519-walk-panel, rows x25519-row-{i} holding
 * x25519-bit-{i} and x25519-swap-{i} (data-swap), and x25519-result. The real curve's offered picks are curve-real-sample-{s} (Echo's id; Nancy's
 * plan named none).
 * The screens are not built yet: each clause reads NOT RUN until its walk opens.
 */

test.describe.configure({ timeout: 120_000 });
test.use({ actionTimeout: 15_000 });

type Pt = { x: number; y: number } | null;
const pt = (o: any): Pt => (o && o.infinity ? null : { x: Number(o?.x), y: Number(o?.y) });
const same = (a: Pt, b: Pt) => (a === null || b === null ? a === b : a.x === b.x && a.y === b.y);
const show = (p: Pt) => (p === null ? 'O' : `(${p.x}, ${p.y})`);
const close = (a: Pt, b: Pt) => a !== null && b !== null && Math.abs(a.x - b.x) < 1e-9 && Math.abs(a.y - b.y) < 1e-9;

/** The point an element shows: data-point="O" is the point at infinity, else data-x and data-y. */
async function shownPt(el: Locator): Promise<Pt> {
  if ((await el.getAttribute('data-point')) === 'O') return null;
  return { x: Number(await el.getAttribute('data-x')), y: Number(await el.getAttribute('data-y')) };
}

/** The scatter element for a toy point: curve-point-{x}-{y}, or curve-point-O. */
const dotId = (p: Pt) => (p === null ? 'curve-point-O' : `curve-point-${p.x}-${p.y}`);

/** Opens Techniques, then the named walk. No such walk reads NOT RUN, never PASS. */
async function openWalk(page: Page, item: string, root: string): Promise<void> {
  requireLive();
  await openApp(page);
  const section = page.getByTestId('section-techniques');
  if ((await section.count()) === 0) throw controlMissing('section-techniques', 'the top bar has no section-techniques');
  await section.click();
  const rail = page.getByTestId(item);
  if ((await rail.count()) === 0) throw controlMissing(item, `the Techniques rail has no ${item}`);
  await rail.click();
  const panel = page.getByTestId('walk-root').getByTestId(root);
  try { await panel.waitFor({ state: 'visible', timeout: 15_000 }); }
  catch { throw controlMissing(root, `${item} opens no ${root} inside walk-root yet`); }
}
const openCurve = (page: Page) => openWalk(page, 'walk-item-curve', 'curve-walk-panel');

async function walk(route: string): Promise<any> {
  const r = await hostGet(route);
  if (r.status === 404) throw new NotRun('PRODUCT_MISSING', `the Host has no ${route} yet`);
  expect(r.status, `GET ${route}`).toBe(200);
  return r.body;
}

test('[A19.ui.toy-curve-scatter-shows-every-point] the GF(17) scatter shows the engine\'s 18 points as dots, plus O', async ({ page }) => {
  const toy = await walk('/api/walk/toy-curve');
  const want: Pt[] = (toy.points ?? []).map(pt).filter((p: Pt) => p !== null);
  expect(want.length, 'the engine lists 18 finite points (R7: 18 points plus O = 19)').toBe(18);
  await openCurve(page);
  const scatter = page.getByTestId('curve-scatter');
  await expect(scatter, 'the walk shows the scatter').toBeVisible();
  expect(await scatter.locator('[data-testid^="curve-point-"][data-x]').count(), 'the scatter draws one dot per finite point').toBe(18);
  for (const w of want) {
    const dot = scatter.getByTestId(dotId(w));
    await expect(dot, `the scatter has the dot ${show(w)}`).toHaveCount(1);
    expect(same(await shownPt(dot), w), `the dot ${show(w)} carries its own x and y`).toBe(true);
  }
  await expect(page.getByTestId('curve-point-O'), 'the walk shows O, the point at infinity').toBeVisible();
});

test('[A19.ui.real-curve-chord-and-reflection] the real-curve picture draws P, Q, the chord, R\' and its reflection R, from the engine', async ({ page }) => {
  const real = await walk('/api/walk/real-curve');
  await openCurve(page);
  const c = real.chord;
  for (const [id, key] of [['curve-real-point-p', 'p'], ['curve-real-point-q', 'q'], ['curve-real-point-r-prime', 'rPrime'], ['curve-real-point-r', 'r']] as [string, string][]) {
    const el = page.getByTestId(id);
    await expect(el, `the real-curve picture shows ${key}`).toBeVisible();
    const got = await shownPt(el);
    expect(close(got, pt(c[key])), `${key} is the engine's (${c[key].x}, ${c[key].y}), and the screen shows ${show(got)}`).toBe(true);
  }
  await expect(page.getByTestId('curve-real-chord'), 'the picture draws the chord through P and Q').toBeVisible();
  await expect(page.getByTestId('curve-real-reflect'), 'the picture draws the reflection from R\' to R').toBeVisible();
});

test('[A19.ui.real-curve-tangent-doubling] picking the offered tangent draws the tangent at P, and R\' and R from the engine', async ({ page }) => {
  const real = await walk('/api/walk/real-curve');
  const s = Array.isArray(real.samples) ? real.samples.findIndex((e: any) => e.kind === 'tangent') : -1;
  expect(s, '/api/walk/real-curve offers a tangent sample (CONTRACT.md, real-curve row)').toBeGreaterThanOrEqual(0);
  const t = real.samples[s];
  await openCurve(page);
  await page.getByTestId(`curve-real-sample-${s}`).click();
  await expect(page.getByTestId('curve-real-tangent'), 'the doubling view draws the tangent line').toBeVisible();
  for (const [id, key] of [['curve-real-point-p', 'p'], ['curve-real-point-r-prime', 'rPrime'], ['curve-real-point-r', 'r']] as [string, string][]) {
    const got = await shownPt(page.getByTestId(id));
    expect(close(got, pt(t[key])), `tangent ${key} is the engine's, and the screen shows ${show(got)}`).toBe(true);
  }
});

test('[A19.ui.toy-curve-free-pick] picking any 2 dots shows the engine\'s sum and slope from /api/walk/toy-curve/add, a double included', async ({ page }) => {
  const toy = await walk('/api/walk/toy-curve');
  const list: Pt[] = [...(toy.points ?? []).map(pt), null];   // the engine's index order; 18 is O
  await walk('/api/walk/toy-curve/add?p=0&q=0');
  await openCurve(page);
  for (const [i, j] of [[1, 7], [4, 4], [2, 18]] as [number, number][]) {
    const want = await walk(`/api/walk/toy-curve/add?p=${i}&q=${j}`);
    await page.getByTestId(dotId(list[i])).click();
    await expect(page.getByTestId(dotId(list[i])), `pick ${i} is P`).toHaveAttribute('data-picked', 'P');
    await page.getByTestId(dotId(list[j])).click();
    if (i !== j) await expect(page.getByTestId(dotId(list[j])), `pick ${j} is Q`).toHaveAttribute('data-picked', 'Q');
    const r = page.getByTestId('curve-point-r');
    await expect(r, `picking ${i} and ${j} shows the sum R`).toBeVisible();
    expect(same(await shownPt(r), pt(want.step.result)), `picking ${i} and ${j} shows the engine's ${show(pt(want.step.result))}`).toBe(true);
    if (i === j) await expect(page.getByTestId('curve-tangent'), 'a double shows the tangent').toBeVisible();
    if (want.step.lambda !== null) {
      const slope = page.getByTestId('curve-slope');
      for (const [id, key] of [['curve-slope-num', 'numerator'], ['curve-slope-den', 'denominator'], ['curve-slope-lambda', 'lambda']] as [string, string][])
        expect(((await slope.getByTestId(id).textContent()) ?? '').trim(), `the slope panel shows the engine's ${key}, ${want.step[key]}`).toBe(String(want.step[key]));
      expect(((await slope.getByTestId('curve-slope-inverse').textContent()) ?? '').trim(), `the slope panel shows the engine's inverse, ${want.step.inverse.value}`).toContain(String(want.step.inverse.value));
    }
  }
});

test('[A19.ui.real-curve-offered-picks] each offered real-curve pick draws the engine\'s P, Q, R\' and R', async ({ page }) => {
  const real = await walk('/api/walk/real-curve');
  expect(Array.isArray(real.samples), '/api/walk/real-curve has samples (CONTRACT.md, real-curve row)').toBe(true);
  await openCurve(page);
  for (let s = 0; s < real.samples.length; s++) {
    const e = real.samples[s];
    await page.getByTestId(`curve-real-sample-${s}`).click();
    for (const [id, key] of [['curve-real-point-p', 'p'], ['curve-real-point-q', 'q'], ['curve-real-point-r-prime', 'rPrime'], ['curve-real-point-r', 'r']] as [string, string][]) {
      const got = await shownPt(page.getByTestId(id));
      expect(close(got, pt(e[key])), `sample ${s} (${e.kind}) ${key} is the engine's, and the screen shows ${show(got)}`).toBe(true);
    }
  }
});

test('[A19.ui.toy-curve-hops-close-at-19] k*G hops through the dots, one hop per k, and the 19th lands on O', async ({ page }) => {
  const toy = await walk('/api/walk/toy-curve');
  const hops: any[] = toy.hops ?? [];
  expect(hops.length, 'the engine gives 19 hops').toBe(19);
  await openCurve(page);
  expect(((await page.getByTestId('curve-hop-count').textContent()) ?? '').trim(), 'the hop count is the engine\'s order').toContain(String(toy.curve?.order ?? 19));
  for (let i = 0; i < 19; i++) {
    const row = page.getByTestId(`curve-hop-${i}`);
    await expect(row, `hop ${i} shows`).toHaveCount(1);
    expect(same(await shownPt(row), pt(hops[i].point)), `hop k=${hops[i].k} lands on the engine's ${show(pt(hops[i].point))}`).toBe(true);
  }
  expect(await shownPt(page.getByTestId('curve-hop-18')), 'the 19th hop lands on O, so the order is 19').toBeNull();
});

test('[A19.ui.toy-curve-double-and-add-k13] the double-and-add rows walk k = 13\'s bits, and end on the engine\'s 13G', async ({ page }) => {
  const toy = await walk('/api/walk/toy-curve');
  expect(Number(toy.k), 'the engine walks k = 13 (R7)').toBe(13);
  const dad: any[] = toy.doubleAndAdd ?? [];
  // 13 is 1101 in binary. The bits come from the rule here, not from the app or the engine.
  const bits = (13).toString(2).split('').map(Number);
  expect(dad.length, 'one engine row per bit of 13').toBe(bits.length);
  await openCurve(page);
  for (let i = 0; i < dad.length; i++) {
    await expect(page.getByTestId(`curve-dna-row-${i}`), `row ${i} shows`).toHaveCount(1);
    expect(((await page.getByTestId(`curve-dna-bit-${i}`).textContent()) ?? '').trim(), `row ${i} shows bit ${bits[i]} of 13`).toBe(String(bits[i]));
    expect(same(await shownPt(page.getByTestId(`curve-dna-point-${i}`)), pt(dad[i].after)), `row ${i} shows the engine's running point ${show(pt(dad[i].after))}`).toBe(true);
  }
});

test('[A19.ui.toy-curve-ecdsa-nonce-reuse] the reuse panel shows 2 signatures with one nonce, and recovers the key on the video\'s values', async ({ page }) => {
  const toy = await walk('/api/walk/toy-curve');
  const ec = toy.ecdsa, rec = ec?.recovery;
  // The video's values (4Tfmwxr0I34), as #249's Host clause pins them: private key 7, reused nonce 3.
  expect(Number(ec.signerPrivate), 'the engine signs with the video\'s private key, 7').toBe(7);
  expect(Number(rec.nonce), 'the engine recovers the video\'s nonce, 3').toBe(3);
  expect(Number(rec.privateKey), 'the engine recovers the private key 7').toBe(7);
  expect(Number(ec.first.r), 'both signatures share r, which is what a reused nonce shows').toBe(Number(ec.second.r));
  await openCurve(page);
  const panel = page.getByTestId('curve-reuse-panel');
  await expect(panel, 'the walk shows the nonce-reuse panel').toBeVisible();
  const fields: [string, unknown][] = [
    ['curve-reuse-d', ec.signerPrivate], ['curve-reuse-k', ec.first.nonce], ['curve-reuse-r', ec.first.r], ['curve-reuse-s1', ec.first.s], ['curve-reuse-s2', ec.second.s],
    ['curve-reuse-z1', ec.first.z], ['curve-reuse-z2', ec.second.z], ['curve-reuse-recovered-d', rec.privateKey],
  ];
  for (const [id, value] of fields)
    expect(((await panel.getByTestId(id).textContent()) ?? '').trim(), `${id} shows the engine's number, ${value}`).toBe(String(value));
});

/** RFC 7748 section 6.1's Alice public key, read from the vector file, not from the engine. */
function rfc7748AlicePublic(): string {
  const text = fs.readFileSync(path.join(__dirname, '..', 'vectors', 'x25519-rfc7748.nsv'), 'utf8');
  const section = text.split(/^\[x25519-dh\]/m)[1] ?? '';
  const m = section.match(/^a_pub\s*=\s*(?<hex>[0-9a-f]+)/m);
  if (!m?.groups) throw new Error('vectors/x25519-rfc7748.nsv has no a_pub in [x25519-dh]');
  return m.groups.hex;
}

test('[A19.ui.x25519-ladder-rows-and-rfc-result] the X25519 screen shows one ladder row per bit with its swap, and ends on RFC 7748\'s value', async ({ page }) => {
  const x = await walk('/api/walk/x25519?step=alice-public');
  const rows: any[] = x.rows ?? [];
  expect(rows.length, 'the engine gives 255 rows, bit 254 down to 0').toBe(255);
  // CONTRACT.md's swap row: swap is the clamped key bit k_t (this engine swaps in, steps, swaps back), not RFC 7748's k_t XOR k_(t+1).
  // The Host clause A19.host.x25519-rows-carry-swap checks it against the clamped RFC 7748 scalar.
  for (let i = 0; i < 255; i++) {
    expect(typeof rows[i].swap, `the engine's row ${i} carries a swap field`).toBe('boolean');
    expect(rows[i].swap, `the engine's row ${i} swap is its bit`).toBe(!!rows[i].isOne);
  }
  await openWalk(page, 'walk-item-x25519', 'x25519-walk-panel');
  expect(await page.locator('[data-testid^="x25519-row-"]').count(), 'the screen shows one row per bit').toBe(255);
  for (const i of [0, 1, 2, 100, 200, 253, 254]) {
    expect(((await page.getByTestId(`x25519-bit-${i}`).textContent()) ?? '').trim(), `row ${i} shows the engine's bit`).toBe(rows[i].isOne ? '1' : '0');
    expect(await page.getByTestId(`x25519-swap-${i}`).getAttribute('data-swap'), `row ${i} shows the engine's swap, ${rows[i].swap}`).toBe(String(rows[i].swap));
  }
  const want = rfc7748AlicePublic();
  expect(String(x.result).toLowerCase(), 'the engine result is RFC 7748\'s Alice public key').toBe(want);
  expect(((await page.getByTestId('x25519-result').textContent()) ?? '').replace(/\s+/g, '').toLowerCase(), 'the screen ends on RFC 7748\'s value').toBe(want);
});
