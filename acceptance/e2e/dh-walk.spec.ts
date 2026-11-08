import { expect, test, type Page } from '@playwright/test';
import { HOST_PORT, NotRun, TOKEN, hostGet, openApp, readState, requireLive } from './support';

/**
 * P7, the Diffie-Hellman walk screen (docs/sections-plan.md section 5, "The Diffie-Hellman walk shows paint chips beside the numbers").
 * Each value has a colour chip, so the colours show the two sides' secrets converging on one shared key:
 *   client private red, server private blue, g yellow, client public and "from the client" orange, server public and "from the server"
 *   green, the shared secret on both sides brown, n (the prime) no chip.
 * The numbers stay the engine's (R5): the screen shows GET /api/walk/dh's values, and these clauses read them from the Host's own reply.
 * Colour never carries meaning alone (docs/ux-design.md line 187): each chip has a name for screen readers that holds its colour word, and a
 * visible letter in DH notation (a, b, g, A, B, s), with a legend that names each colour beside its letter.
 * The walk runs on a public practice exponent, so it stays open with Show keys OFF (sections-plan.md section 4, the "key decides" rule).
 *
 * Test ids (Nancy's P7 plan, 2026-11-07): walk-item-dh opens dh-walk-panel inside walk-root. Each value row is dh-value-{name}, with the
 * engine's number string, unchanged, in dh-value-{name}-number. Its chip is dh-chip-{name}, with data-chip="{colour}", data-letter="{letter}",
 * the letter as its visible text, and an aria-label that names the colour. The legend is dh-chip-legend. The note is dh-real-size, with
 * realExponentBits in dh-real-size-bits. Names: client-private, server-private, g, client-public, server-public, client-shared,
 * server-shared, n. The plan also gives "from the client" and "from the server" their chips: dh-chip-from-client and dh-chip-from-server.
 * Where Techniques opens a DH walk and a chip is wrong or missing, these clauses FAIL. They read NOT RUN only when there is no DH walk at all.
 */

test.describe.configure({ timeout: 120_000 });
test.use({ actionTimeout: 15_000 });

/** sections-plan.md section 5's colours, and the DH letters for the visible cue. No value comes from the app. */
const VALUES: { name: string; colour: string | null; letter: string | null }[] = [
  { name: 'client-private', colour: 'red', letter: 'a' },
  { name: 'server-private', colour: 'blue', letter: 'b' },
  { name: 'g', colour: 'yellow', letter: 'g' },
  { name: 'client-public', colour: 'orange', letter: 'A' },
  { name: 'server-public', colour: 'green', letter: 'B' },
  { name: 'client-shared', colour: 'brown', letter: 's' },
  { name: 'server-shared', colour: 'brown', letter: 's' },
  { name: 'n', colour: null, letter: null },
];
/** "from the client" and "from the server": chips with no value row of their own. */
const FROM: { name: string; colour: string; letter: string }[] = [
  { name: 'from-client', colour: 'orange', letter: 'A' },
  { name: 'from-server', colour: 'green', letter: 'B' },
];

/** The Host's { hex, dec } for each value row, from GET /api/walk/dh. A power holds result { hex, dec }. */
function num(v: any): { hex: string; dec: string } {
  const n = v && typeof v.dec === 'string' ? v : v?.result;
  return { hex: String(n?.hex ?? '').toLowerCase(), dec: String(n?.dec ?? '') };
}
function hostValues(walk: any): Record<string, { hex: string; dec: string }> {
  return {
    'client-private': num(walk.client?.private), 'server-private': num(walk.server?.private), 'g': num(walk.generator),
    'client-public': num(walk.client?.public), 'server-public': num(walk.server?.public),
    'client-shared': num(walk.client?.shared), 'server-shared': num(walk.server?.shared), 'n': num(walk.prime),
  };
}

/** The screen shows the engine's string unchanged, and a long one may wrap. So white space goes, and the rest must equal dec or hex. */
function showsHostNumber(text: string | null, want: { hex: string; dec: string }): boolean {
  const t = (text ?? '').replace(/\s+/g, '');
  return t.length > 0 && (t === want.dec || t.toLowerCase() === want.hex || t.toLowerCase() === '0x' + want.hex);
}

// The Origin is the built-in http://localhost:5173, which the Host allows with or without NETSEC_ORIGINS (#225).
async function setShowKeys(on: boolean): Promise<void> {
  const live = readState();
  if (!live.hostUp || !live.previewUp) return;
  const r = await fetch(`http://127.0.0.1:${HOST_PORT}/api/security/show-keys`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}`, Origin: 'http://localhost:5173' }, body: JSON.stringify({ on }),
  });
  expect(r.ok, 'PUT show-keys').toBe(true);
}

/** Opens Techniques, then its Diffie-Hellman item. Returns once dh-walk-panel shows inside walk-root. No DH walk reads NOT RUN. */
async function openDh(page: Page): Promise<void> {
  requireLive();
  await openApp(page);
  const section = page.getByTestId('section-techniques');
  if ((await section.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the top bar has no section-techniques');
  await section.click();
  const item = page.getByTestId('walk-item-dh');
  if ((await item.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the Techniques rail has no walk-item-dh');
  await item.click();
  const panel = page.getByTestId('walk-root').getByTestId('dh-walk-panel');
  try { await panel.waitFor({ state: 'visible', timeout: 15_000 }); }
  catch { throw new NotRun('UI_CONTROL_MISSING', 'walk-item-dh opens no dh-walk-panel inside walk-root yet (slice P7)'); }
}

/** The small group's walk, which the screen opens on. A Host with no DH route reads NOT RUN. */
async function smallWalk(): Promise<any> {
  const r = await hostGet('/api/walk/dh?group=small');
  if (r.status === 404) throw new NotRun('PRODUCT_MISSING', 'the Host has no /api/walk/dh yet');
  expect(r.status, 'GET /api/walk/dh?group=small').toBe(200);
  return r.body;
}

test('[A19.ui.dh-chips-match-the-plan] each DH value shows the Host\'s number and the plan\'s chip colour, and n has no chip', async ({ page }) => {
  const want = hostValues(await smallWalk());
  await openDh(page);
  for (const v of VALUES) {
    await expect(page.getByTestId(`dh-value-${v.name}`), `the walk shows the ${v.name} row`).toBeVisible();
    expect(want[v.name].dec, `the Host's walk has a number for ${v.name}`).not.toBe('');
    const shown = await page.getByTestId(`dh-value-${v.name}-number`).textContent();
    expect(showsHostNumber(shown, want[v.name]), `${v.name} shows the Host's number unchanged (R5); it shows "${shown}", the Host gives ${want[v.name].dec}`).toBe(true);
    const chip = page.getByTestId(`dh-chip-${v.name}`);
    if (v.colour === null) { expect(await chip.count(), 'n, the prime, has no chip').toBe(0); continue; }
    await expect(chip, `${v.name} has a chip`).toBeVisible();
    expect(await chip.getAttribute('data-chip'), `${v.name}'s chip is ${v.colour}`).toBe(v.colour);
  }
  for (const f of FROM) {
    const chip = page.getByTestId(`dh-chip-${f.name}`);
    await expect(chip, `"${f.name.replace('-', ' the ')}" has a chip`).toBeVisible();
    expect(await chip.getAttribute('data-chip'), `${f.name}'s chip is ${f.colour}`).toBe(f.colour);
  }
  // The point of the chips: the two shared values are one number, in one colour.
  expect(want['client-shared'].dec, 'the two sides reach one shared secret').toBe(want['server-shared'].dec);
});

test('[A19.ui.dh-chips-not-colour-alone] each chip names its colour for screen readers and shows its DH letter, and a legend pairs them', async ({ page }) => {
  await smallWalk();
  await openDh(page);
  for (const c of [...VALUES.filter(v => v.colour !== null), ...FROM] as { name: string; colour: string; letter: string }[]) {
    const chip = page.getByTestId(`dh-chip-${c.name}`);
    await expect(chip, `${c.name} has a chip`).toBeVisible();
    const label = (await chip.getAttribute('aria-label')) ?? '';
    expect(label.toLowerCase(), `${c.name}'s chip has an aria-label with the word ${c.colour}`).toContain(c.colour);
    expect(await chip.getAttribute('data-letter'), `${c.name}'s chip carries the letter ${c.letter}`).toBe(c.letter);
    expect(((await chip.innerText()) ?? '').trim(), `${c.name}'s chip shows the letter ${c.letter}, so the colour is not the only cue`).toBe(c.letter);
  }
  const legend = page.getByTestId('dh-chip-legend');
  await expect(legend, 'the walk shows a chip legend').toBeVisible();
  const text = ((await legend.innerText()) ?? '').toLowerCase();
  for (const colour of ['red', 'blue', 'yellow', 'orange', 'green', 'brown']) expect(text, `the legend names ${colour}`).toContain(colour);
});

test('[A19.ui.dh-real-size-note-reads-the-host] the real-size note shows the Host\'s realExponentBits, not a number of its own', async ({ page }) => {
  const walk = await smallWalk();
  const real = Number(walk.realExponentBits);
  expect(real >= 224, `the Host reports realExponentBits ${walk.realExponentBits}, at least 224`).toBe(true);
  // The screen must read the field. So the reply the page gets carries a different value, and the note must show that one.
  const planted = real === 333 ? 334 : 333;
  await page.route(/\/api\/walk\/dh(\?|$)/, async route => {
    const resp = await route.fetch();
    const body = await resp.json();
    await route.fulfill({ response: resp, json: { ...body, realExponentBits: planted } });
  });
  await openDh(page);
  await expect(page.getByTestId('dh-real-size'), 'the walk shows the real-size note').toBeVisible();
  expect(((await page.getByTestId('dh-real-size-bits').textContent()) ?? '').trim(), `the note shows the value from the reply (${planted})`).toBe(String(planted));
  expect((await page.getByTestId('dh-real-size').innerText()) ?? '', `the note does not show a fixed ${real}`).not.toContain(String(real));
});

test('[A19.ui.dh-open-with-show-keys-off] with Show keys OFF the DH walk still shows its teaching numbers and chips', async ({ page }) => {
  const want = hostValues(await smallWalk());
  await setShowKeys(false);
  try {
    const off = await hostGet('/api/walk/dh?group=small');
    expect(off.status, 'OFF: the Host keeps /api/walk/dh open, since it runs on a public practice exponent').toBe(200);
    await openDh(page);
    for (const name of ['client-private', 'server-private', 'client-shared']) {
      const shown = await page.getByTestId(`dh-value-${name}-number`).textContent();
      expect(showsHostNumber(shown, want[name]), `OFF: ${name} still shows the Host's number; it shows "${shown}"`).toBe(true);
      await expect(page.getByTestId(`dh-chip-${name}`), `OFF: ${name} keeps its chip`).toBeVisible();
    }
  } finally {
    await setShowKeys(true);
  }
});
