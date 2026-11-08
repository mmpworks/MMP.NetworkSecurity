import { expect, test, type Page } from '@playwright/test';
import { HOST_PORT, NotRun, TOKEN, hostGet, openApp, readState, requireLive } from './support';

/**
 * P7, the Diffie-Hellman walk screen (docs/sections-plan.md section 5, "The Diffie-Hellman walk shows paint chips beside the numbers").
 * Each value has a colour chip, so the colours show the two sides' secrets converging on one shared key:
 *   client private red, server private blue, g yellow, client public and "from the client" orange, server public and "from the server"
 *   green, the shared secret on both sides brown, n (the prime) no chip.
 * The numbers stay the engine's (R5): the screen shows GET /api/walk/dh's values, and these clauses read them from the Host's own reply.
 * Colour never carries meaning alone (docs/ux-design.md line 187): each chip has a name for screen readers and one visible cue.
 * The walk runs on a public practice exponent, so it stays open with Show keys OFF (sections-plan.md section 4, the "key decides" rule).
 *
 * Test ids (DRAFT, until Nancy confirms her P7 plan): dh-walk-root on the walk; dh-value-{name} on each value row, its number in
 * dh-num-{name}; dh-chip-{name} on its chip, with data-chip="{colour}" and an accessible name that names the colour; dh-real-size on the
 * real-size note. Names: client-private, server-private, generator, client-public, server-public, from-client, from-server, client-shared,
 * server-shared, prime.
 * Where Techniques opens a DH walk and a chip is wrong or missing, these clauses FAIL. They read NOT RUN only when there is no DH walk at all.
 */

test.describe.configure({ timeout: 120_000 });
test.use({ actionTimeout: 15_000 });

/** sections-plan.md section 5's table, written out from the plan. No value comes from the app. */
const CHIPS: Record<string, string | null> = {
  'client-private': 'red',
  'server-private': 'blue',
  'generator': 'yellow',
  'client-public': 'orange',
  'from-client': 'orange',
  'server-public': 'green',
  'from-server': 'green',
  'client-shared': 'brown',
  'server-shared': 'brown',
  'prime': null,
};

/** The Host's decimal for each named value, from GET /api/walk/dh. A power or a number is { hex, dec }, or a power holds result { hex, dec }. */
function dec(v: any): string {
  if (v && typeof v.dec === 'string') return v.dec;
  if (v && v.result && typeof v.result.dec === 'string') return v.result.dec;
  return '';
}
function hostValues(walk: any): Record<string, string> {
  return {
    'client-private': dec(walk.client?.private), 'server-private': dec(walk.server?.private), 'generator': dec(walk.generator),
    'client-public': dec(walk.client?.public), 'from-client': dec(walk.client?.public),
    'server-public': dec(walk.server?.public), 'from-server': dec(walk.server?.public),
    'client-shared': dec(walk.client?.shared), 'server-shared': dec(walk.server?.shared), 'prime': dec(walk.prime),
  };
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

/** Opens Techniques, then its Diffie-Hellman item. Returns once dh-walk-root shows. No DH walk in Techniques reads NOT RUN. */
async function openDh(page: Page): Promise<void> {
  requireLive();
  await openApp(page);
  const section = page.getByTestId('section-techniques');
  if ((await section.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the top bar has no section-techniques');
  await section.click();
  const item = page.getByTestId('walk-item-dh');
  if ((await item.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the Techniques rail has no walk-item-dh');
  await item.click();
  const root = page.getByTestId('dh-walk-root');
  try { await root.waitFor({ state: 'visible', timeout: 15_000 }); }
  catch { throw new NotRun('UI_CONTROL_MISSING', 'walk-item-dh opens no dh-walk-root yet (slice P7)'); }
}

/** The small group's walk, which the screen opens on. A Host with no DH route reads NOT RUN. */
async function smallWalk(): Promise<any> {
  const r = await hostGet('/api/walk/dh?group=small');
  if (r.status === 404) throw new NotRun('PRODUCT_MISSING', 'the Host has no /api/walk/dh yet');
  expect(r.status, 'GET /api/walk/dh?group=small').toBe(200);
  return r.body;
}

/** Digits only, so a thousands separator or a line break inside a long number does not hide a match. */
const digits = (s: string | null) => (s ?? '').replace(/[^0-9]/g, '');

test('[A19.ui.dh-chips-match-the-plan] each DH value shows the Host\'s number and the plan\'s chip colour, and n has no chip', async ({ page }) => {
  const walk = await smallWalk();
  const want = hostValues(walk);
  await openDh(page);
  for (const [name, colour] of Object.entries(CHIPS)) {
    const row = page.getByTestId(`dh-value-${name}`);
    await expect(row, `the walk shows the ${name} row`).toBeVisible();
    expect(want[name], `the Host's walk has a decimal for ${name}`).not.toBe('');
    expect(digits(await page.getByTestId(`dh-num-${name}`).textContent()), `${name} shows the Host's number (R5)`).toBe(want[name]);
    const chip = page.getByTestId(`dh-chip-${name}`);
    if (colour === null) { expect(await chip.count(), 'n, the prime, has no chip').toBe(0); continue; }
    await expect(chip, `${name} has a chip`).toBeVisible();
    expect(await chip.getAttribute('data-chip'), `${name}'s chip is ${colour}`).toBe(colour);
  }
  // The point of the chips: the two shared values are one number, in one colour.
  expect(want['client-shared'], 'the two sides reach one shared secret').toBe(want['server-shared']);
});

test('[A19.ui.dh-chips-not-colour-alone] each chip has a name for screen readers that names its colour, and one visible cue', async ({ page }) => {
  await smallWalk();
  await openDh(page);
  const seen: string[] = [];
  for (const [name, colour] of Object.entries(CHIPS)) {
    if (colour === null) continue;
    const chip = page.getByTestId(`dh-chip-${name}`);
    await expect(chip, `${name} has a chip`).toBeVisible();
    // The accessible name, as a screen reader gets it (aria-label, aria-labelledby, or title).
    const label = (await chip.evaluate(el => el.getAttribute('aria-label') ?? (el.getAttribute('aria-labelledby') ? document.getElementById(el.getAttribute('aria-labelledby')!)?.textContent : null) ?? el.getAttribute('title') ?? '')) ?? '';
    expect(label.toLowerCase(), `${name}'s chip has an accessible name with the word ${colour}`).toContain(colour);
    // DRAFT: the visible cue is the chip's own visible text (a letter or a word). Nancy's plan may name another cue.
    const cue = ((await chip.innerText()) ?? '').trim();
    expect(cue.length, `${name}'s chip shows a visible cue beside its colour`).toBeGreaterThan(0);
    seen.push(`${name}=${colour}:${cue}`);
  }
  // Two values share a colour only when the plan gives them the same colour, so the cue may repeat only there.
  const cueOf = (n: string) => seen.find(s => s.startsWith(n + '='))!.split(':')[1];
  expect(cueOf('client-private'), 'red and blue chips show different cues').not.toBe(cueOf('server-private'));
  expect(cueOf('client-public'), 'orange and green chips show different cues').not.toBe(cueOf('server-public'));
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
  const note = page.getByTestId('dh-real-size');
  await expect(note, 'the walk shows the real-size note').toBeVisible();
  const text = (await note.innerText()) ?? '';
  expect(text, `the note shows the value from the reply (${planted})`).toContain(String(planted));
  expect(text, `the note does not show a fixed ${real}`).not.toContain(String(real));
});

test('[A19.ui.dh-open-with-show-keys-off] with Show keys OFF the DH walk still shows its teaching numbers and chips', async ({ page }) => {
  const walk = await smallWalk();
  const want = hostValues(walk);
  await setShowKeys(false);
  try {
    const off = await hostGet('/api/walk/dh?group=small');
    expect(off.status, 'OFF: the Host keeps /api/walk/dh open, since it runs on a public practice exponent').toBe(200);
    await openDh(page);
    for (const name of ['client-private', 'server-private', 'client-shared']) {
      expect(digits(await page.getByTestId(`dh-num-${name}`).textContent()), `OFF: ${name} still shows the Host's number`).toBe(want[name]);
      await expect(page.getByTestId(`dh-chip-${name}`), `OFF: ${name} keeps its chip`).toBeVisible();
    }
  } finally {
    await setShowKeys(true);
  }
});
