import { expect, test, type Locator, type Page } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { NotRun, hostGet, openApp, requireLive } from './support';

/**
 * R7, the elliptic-curve walk screens (docs/sections-plan.md R7 and section 4, slices P8a and P8). They teach in the order of video
 * 4Tfmwxr0I34: the chord rule on the real curve (P, Q, the third point R', the reflection R), tangent doubling, then the same curve over
 * GF(17) as a scatter of 18 points plus O, k*G as hops through the dots with order 19, double-and-add on k = 13's bits, and ECDSA on the toy
 * curve, where a reused nonce gives away the key. The X25519 screen shows the Montgomery ladder, one row per bit.
 * Every number comes from the engine (R5): /api/walk/real-curve, /api/walk/toy-curve and /api/walk/x25519. These clauses read the same
 * replies and compare. The X25519 result is also checked against RFC 7748 section 6.1 in vectors/x25519-rfc7748.nsv, not the engine.
 * The screens are not built yet: each clause reads NOT RUN until its walk opens. Test ids are in IDS below (DRAFT until Nancy confirms).
 */

test.describe.configure({ timeout: 120_000 });
test.use({ actionTimeout: 15_000 });

/** Every test id these clauses read, in one place. A point element carries data-x and data-y, or data-infinity="true". */
const IDS = {
  toyItem: 'walk-item-toy-curve', toyRoot: 'toy-curve-walk-panel',
  dot: 'toy-dot', infinity: 'toy-dot-infinity',
  chordP: 'real-chord-p', chordQ: 'real-chord-q', chordRPrime: 'real-chord-rprime', chordR: 'real-chord-r', chordLine: 'real-chord-line', chordReflect: 'real-chord-reflect',
  tangentP: 'real-tangent-p', tangentRPrime: 'real-tangent-rprime', tangentR: 'real-tangent-r', tangentLine: 'real-tangent-line',
  hop: 'toy-hop', dadRow: 'toy-dad-row', dadK: 'toy-dad-k',
  ecdsa: 'toy-ecdsa-recovery',
  x25519Item: 'walk-item-x25519', x25519Root: 'x25519-walk-panel', ladderRow: 'x25519-row', ladderResult: 'x25519-result',
};

type Pt = { x: number; y: number } | null;
const pt = (o: any): Pt => (o && o.infinity ? null : { x: Number(o?.x), y: Number(o?.y) });
const same = (a: Pt, b: Pt) => (a === null || b === null ? a === b : a.x === b.x && a.y === b.y);
const show = (p: Pt) => (p === null ? 'O' : `(${p.x}, ${p.y})`);

/** The point an element shows, from its data-x and data-y, or O from data-infinity="true". */
async function shownPt(el: Locator): Promise<Pt> {
  if ((await el.getAttribute('data-infinity')) === 'true') return null;
  return { x: Number(await el.getAttribute('data-x')), y: Number(await el.getAttribute('data-y')) };
}

/** Opens Techniques, then the named walk. No such walk reads NOT RUN, never PASS. */
async function openWalk(page: Page, item: string, root: string): Promise<void> {
  requireLive();
  await openApp(page);
  const section = page.getByTestId('section-techniques');
  if ((await section.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the top bar has no section-techniques');
  await section.click();
  const rail = page.getByTestId(item);
  if ((await rail.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', `the Techniques rail has no ${item}`);
  await rail.click();
  const panel = page.getByTestId('walk-root').getByTestId(root);
  try { await panel.waitFor({ state: 'visible', timeout: 15_000 }); }
  catch { throw new NotRun('UI_CONTROL_MISSING', `${item} opens no ${root} inside walk-root yet`); }
}

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
  await openWalk(page, IDS.toyItem, IDS.toyRoot);
  const dots = page.getByTestId(IDS.dot);
  expect(await dots.count(), 'the scatter draws one dot per finite point').toBe(18);
  const shown: Pt[] = [];
  for (let i = 0; i < 18; i++) shown.push(await shownPt(dots.nth(i)));
  for (const w of want) expect(shown.some(s => same(s, w)), `the scatter has the dot ${show(w)}`).toBe(true);
  await expect(page.getByTestId(IDS.infinity), 'the scatter shows O, the point at infinity').toBeVisible();
});

test('[A19.ui.real-curve-chord-and-reflection] the chord view draws P, Q, the line, the third point R\' and its reflection R, from the engine', async ({ page }) => {
  const real = await walk('/api/walk/real-curve');
  await openWalk(page, IDS.toyItem, IDS.toyRoot);
  const c = real.chord;
  for (const [id, key] of [[IDS.chordP, 'p'], [IDS.chordQ, 'q'], [IDS.chordRPrime, 'rPrime'], [IDS.chordR, 'r']] as [string, string][]) {
    const el = page.getByTestId(id);
    await expect(el, `the chord view shows ${key}`).toBeVisible();
    const got = await shownPt(el);
    expect(got !== null && Math.abs(got.x - Number(c[key].x)) < 1e-9 && Math.abs(got.y - Number(c[key].y)) < 1e-9, `${key} is the engine's (${c[key].x}, ${c[key].y}), and the screen shows ${show(got)}`).toBe(true);
  }
  await expect(page.getByTestId(IDS.chordLine), 'the chord view draws the line through P and Q').toBeVisible();
  await expect(page.getByTestId(IDS.chordReflect), 'the chord view draws the reflection from R\' to R').toBeVisible();
});

test('[A19.ui.real-curve-tangent-doubling] the doubling view draws the tangent at P, and R\' and R from the engine', async ({ page }) => {
  const real = await walk('/api/walk/real-curve');
  await openWalk(page, IDS.toyItem, IDS.toyRoot);
  const t = real.tangent;
  for (const [id, key] of [[IDS.tangentP, 'p'], [IDS.tangentRPrime, 'rPrime'], [IDS.tangentR, 'r']] as [string, string][]) {
    const got = await shownPt(page.getByTestId(id));
    expect(got !== null && Math.abs(got.x - Number(t[key].x)) < 1e-9 && Math.abs(got.y - Number(t[key].y)) < 1e-9, `tangent ${key} is the engine's, and the screen shows ${show(got)}`).toBe(true);
  }
  await expect(page.getByTestId(IDS.tangentLine), 'the doubling view draws the tangent line').toBeVisible();
});

test('[A19.ui.toy-curve-hops-close-at-19] k*G hops through the dots, one hop per k, and the 19th lands on O', async ({ page }) => {
  const toy = await walk('/api/walk/toy-curve');
  const hops: any[] = toy.hops ?? [];
  expect(hops.length, 'the engine gives 19 hops').toBe(19);
  await openWalk(page, IDS.toyItem, IDS.toyRoot);
  const rows = page.getByTestId(IDS.hop);
  expect(await rows.count(), 'the screen shows 19 hops').toBe(19);
  for (let i = 0; i < 19; i++) {
    const row = rows.nth(i);
    expect(Number(await row.getAttribute('data-k')), `hop ${i + 1} names its k`).toBe(Number(hops[i].k));
    expect(same(await shownPt(row), pt(hops[i].point)), `hop k=${hops[i].k} lands on the engine's ${show(pt(hops[i].point))}`).toBe(true);
  }
  expect(await shownPt(rows.nth(18)), 'the 19th hop lands on O, so the order is 19').toBeNull();
});

test('[A19.ui.toy-curve-double-and-add-k13] the double-and-add rows walk k = 13\'s bits, and end on the engine\'s 13G', async ({ page }) => {
  const toy = await walk('/api/walk/toy-curve');
  expect(Number(toy.k), 'the engine walks k = 13 (R7)').toBe(13);
  const dad: any[] = toy.doubleAndAdd ?? [];
  await openWalk(page, IDS.toyItem, IDS.toyRoot);
  expect(((await page.getByTestId(IDS.dadK).textContent()) ?? '').trim(), 'the screen names k = 13').toContain('13');
  const rows = page.getByTestId(IDS.dadRow);
  expect(await rows.count(), 'one row per engine row').toBe(dad.length);
  // 13 is 1101 in binary. The bits come from the rule here, not from the app or the engine.
  const bits = (13).toString(2).split('').map(Number);
  expect(dad.length, 'one row per bit of 13').toBe(bits.length);
  for (let i = 0; i < dad.length; i++) {
    const row = rows.nth(i);
    expect(Number(await row.getAttribute('data-bit')), `row ${i} shows bit ${bits[i]} of 13`).toBe(bits[i]);
    expect(same(await shownPt(row), pt(dad[i].after)), `row ${i} shows the engine's running point ${show(pt(dad[i].after))}`).toBe(true);
  }
});

test('[A19.ui.toy-curve-ecdsa-nonce-reuse] the recovery panel shows 2 signatures with one nonce, and recovers the key on the video\'s values', async ({ page }) => {
  const toy = await walk('/api/walk/toy-curve');
  const ec = toy.ecdsa, rec = ec?.recovery;
  // The video's values (4Tfmwxr0I34), as #249's Host clause pins them: private key 7, reused nonce 3.
  expect(Number(ec.signerPrivate), 'the engine signs with the video\'s private key, 7').toBe(7);
  expect(Number(rec.nonce), 'the engine recovers the video\'s nonce, 3').toBe(3);
  expect(Number(rec.privateKey), 'the engine recovers the private key 7').toBe(7);
  await openWalk(page, IDS.toyItem, IDS.toyRoot);
  const panel = page.getByTestId(IDS.ecdsa);
  await expect(panel, 'the walk shows the nonce-reuse recovery').toBeVisible();
  const fields: [string, unknown][] = [
    ['r', ec.first.r], ['s1', ec.first.s], ['s2', ec.second.s], ['z1', ec.first.z], ['z2', ec.second.z],
    ['nonce', rec.nonce], ['private-key', rec.privateKey],
  ];
  for (const [name, value] of fields) {
    const el = panel.getByTestId(`${IDS.ecdsa}-${name}`);
    expect(((await el.textContent()) ?? '').trim(), `the panel shows the engine's ${name}, ${value}`).toBe(String(value));
  }
  expect(Number(ec.first.r), 'both signatures share r, which is what a reused nonce shows').toBe(Number(ec.second.r));
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
  await openWalk(page, IDS.x25519Item, IDS.x25519Root);
  const shown = page.getByTestId(IDS.ladderRow);
  expect(await shown.count(), 'the screen shows one row per bit').toBe(255);
  // The ladder swaps when this bit differs from the one before it (RFC 7748 section 5: swap ^= k_t). The rule is written here, not read.
  let prev = 0;
  for (const i of [0, 1, 2, 100, 200, 253, 254]) {
    const row = shown.nth(i);
    const bit = rows[i].isOne ? 1 : 0;
    expect(Number(await row.getAttribute('data-bit')), `row ${i} shows the engine's bit ${rows[i].bit}`).toBe(bit);
    prev = i === 0 ? 0 : (rows[i - 1].isOne ? 1 : 0);
    expect(await row.getAttribute('data-swap'), `row ${i} shows the swap as bit ${bit} xor the bit before, ${prev}`).toBe(String((bit ^ prev) === 1));
  }
  const want = rfc7748AlicePublic();
  expect(String(x.result).toLowerCase(), 'the engine result is RFC 7748\'s Alice public key').toBe(want);
  expect(((await page.getByTestId(IDS.ladderResult).textContent()) ?? '').replace(/\s+/g, '').toLowerCase(), 'the screen ends on RFC 7748\'s value').toBe(want);
});
