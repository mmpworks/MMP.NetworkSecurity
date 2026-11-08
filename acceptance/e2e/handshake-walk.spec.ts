import { expect, test, type Page } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { HOST_PORT, NotRun, TOKEN, hostGet, openApp, readState, requireLive } from './support';

/**
 * The Handshake section's key schedule screens (docs/sections-plan.md section 4, slices P4 and P4b; R8).
 * TLS 1.3: /api/walk/tls13/schedule runs on RFC 8448 section 3's public inputs, every Extract and Derive-Secret with its label. The screen
 * names its key as RFC 8448's published test key, and stays open with Show keys OFF (sections-plan.md line 157).
 * TLS 1.1: /api/walk/tls11/schedule is a fixed teaching run on the course's built-in training key, which is public in the source: the
 * pre-master, then the master secret, then the 4 directional keys (line 159, R8). The screen names that key as public, and stays open with
 * Show keys OFF.
 * Every value on screen is the engine's (R5). The TLS 1.3 values whose step name is a field of vectors/tls13-rfc8448.nsv are also checked
 * against the RFC there, not only against the engine.
 * Test ids (agreed with Nancy, 2026-11-08; walk-item-tls11 is "TLS 1.1 with RSA (the old way)", after TLS 1.3, the lead's call): walk-item-tls13 opens tls13-schedule-panel inside walk-root, with one tls13-step-{i} per
 * engine step (data-name), holding tls13-step-label-{i} and tls13-step-output-{i}, and tls13-key-source (data-key-source) as the key's
 * label. walk-item-tls11 (Handshake rail, P4b) opens tls11-schedule-panel, with tls11-premaster, tls11-master, tls11-client-mac-key,
 * tls11-server-mac-key, tls11-client-key, tls11-server-key, tls11-key-log and tls11-key-source (data-key-source).
 * The screens are not built yet: each clause reads NOT RUN until its walk opens.
 */

test.describe.configure({ timeout: 120_000 });
test.use({ actionTimeout: 15_000 });

// The Origin is the built-in http://localhost:5173, which the Host allows with or without NETSEC_ORIGINS (#225).
async function setShowKeys(on: boolean): Promise<void> {
  const live = readState();
  if (!live.hostUp || !live.previewUp) return;
  const r = await fetch(`http://127.0.0.1:${HOST_PORT}/api/security/show-keys`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}`, Origin: 'http://localhost:5173' }, body: JSON.stringify({ on }),
  });
  expect(r.ok, 'PUT show-keys').toBe(true);
}

async function openWalk(page: Page, item: string, root: string): Promise<void> {
  requireLive();
  await openApp(page);
  const section = page.getByTestId('section-handshake');
  if ((await section.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the top bar has no section-handshake');
  await section.click();
  const rail = page.getByTestId(item);
  if ((await rail.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', `the Handshake rail has no ${item}`);
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

const text = async (page: Page, id: string) => ((await page.getByTestId(id).textContent()) ?? '').replace(/\s+/g, '').toLowerCase();

/** RFC 8448 section 3's fields, from the suite's vector file, not from the engine. */
function rfc8448(): Map<string, string> {
  const body = fs.readFileSync(path.join(__dirname, '..', 'vectors', 'tls13-rfc8448.nsv'), 'utf8');
  const m = new Map<string, string>();
  for (const line of body.split(/\r?\n/)) {
    const f = line.match(/^(?<name>[a-z0-9_]+)\s*=\s*(?<value>[0-9a-f]*)\s*$/);
    if (f?.groups) m.set(f.groups.name, f.groups.value);
  }
  return m;
}

/** Shows every TLS 1.3 step, checks its label and output, and returns how many steps matched RFC 8448 directly. */
async function tls13Steps(page: Page, steps: any[]): Promise<number> {
  const rfc = rfc8448();
  expect(await page.locator('[data-testid^="tls13-step-"][data-name]').count(), 'one row per engine step').toBe(steps.length);
  let rfcHits = 0;
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    await expect(page.getByTestId(`tls13-step-${i}`), `step ${i} (${s.name}) shows`).toHaveAttribute('data-name', String(s.name));
    if (s.label) expect(((await page.getByTestId(`tls13-step-label-${i}`).textContent()) ?? ''), `step ${i} shows its label "${s.label}"`).toContain(String(s.label));
    const out = await text(page, `tls13-step-output-${i}`);
    expect(out, `step ${i} (${s.name}) shows the engine's output`).toBe(String(s.output).toLowerCase());
    const want = rfc.get(String(s.name));
    if (want) { expect(out, `step ${i} (${s.name}) shows RFC 8448's value`).toBe(want); rfcHits++; }
  }
  return rfcHits;
}

test('[A19.ui.tls13-schedule-shows-every-step] the TLS 1.3 schedule screen shows each engine step with its label and output, the RFC 8448 fields equal to the RFC', async ({ page }) => {
  const w = await walk('/api/walk/tls13/schedule');
  const steps: any[] = w.steps ?? [];
  expect(steps.length, 'the engine gives 21 steps').toBe(21);
  await openWalk(page, 'walk-item-tls13', 'tls13-schedule-panel');
  const hits = await tls13Steps(page, steps);
  expect(hits, 'at least one shown value is checked against RFC 8448 directly').toBeGreaterThan(0);
});

test('[A19.ui.tls13-schedule-key-labelled-rfc8448] the TLS 1.3 schedule names its key as RFC 8448\'s published test key', async ({ page }) => {
  const w = await walk('/api/walk/tls13/schedule');
  expect(w.keySource, 'the engine runs on RFC 8448\'s inputs').toBe('rfc8448');
  await openWalk(page, 'walk-item-tls13', 'tls13-schedule-panel');
  const label = page.getByTestId('tls13-key-source');
  await expect(label, 'the screen labels its key').toBeVisible();
  expect(await label.getAttribute('data-key-source'), 'the label carries the engine\'s keySource').toBe('rfc8448');
  const words = ((await label.innerText()) ?? '').toLowerCase();
  expect(words.includes('rfc 8448') && words.includes('test'), `the label names RFC 8448's published test key, and reads "${words}"`).toBe(true);
});

test('[A19.ui.tls13-schedule-open-with-show-keys-off] with Show keys OFF the TLS 1.3 schedule still shows every step', async ({ page }) => {
  await walk('/api/walk/tls13/schedule');
  await setShowKeys(false);
  try {
    const off = await walk('/api/walk/tls13/schedule');
    await openWalk(page, 'walk-item-tls13', 'tls13-schedule-panel');
    await tls13Steps(page, off.steps ?? []);
  } finally {
    await setShowKeys(true);
  }
});

const TLS11: [string, (w: any) => string][] = [
  ['tls11-premaster', w => w.premaster],
  ['tls11-master', w => w.masterSecret?.value],
  ['tls11-client-mac-key', w => w.keyBlock?.clientMacKey],
  ['tls11-server-mac-key', w => w.keyBlock?.serverMacKey],
  ['tls11-client-key', w => w.keyBlock?.clientKey],
  ['tls11-server-key', w => w.keyBlock?.serverKey],
];

/** Checks the 6 values and their order: pre-master, then master, then the 4 keys (R8). */
async function tls11Values(page: Page, w: any): Promise<void> {
  for (const [id, pick] of TLS11) expect(await text(page, id), `${id} shows the engine's value`).toBe(String(pick(w)).toLowerCase());
  const order = await page.evaluate((ids: string[]) => ids.map(id => document.querySelector(`[data-testid="${id}"]`)).every((el, i, all) =>
    i === 0 || !!(all[i - 1] && el && (all[i - 1]!.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING))), TLS11.map(t => t[0]));
  expect(order, 'the screen reads pre-master, then master, then the 4 keys, in that order').toBe(true);
}

test('[A19.ui.tls11-schedule-premaster-to-keys] the TLS 1.1 schedule screen walks pre-master to master to the 4 keys, as the engine gives them', async ({ page }) => {
  const w = await walk('/api/walk/tls11/schedule');
  await openWalk(page, 'walk-item-tls11', 'tls11-schedule-panel');
  await tls11Values(page, w);
  expect(await text(page, 'tls11-key-log'), 'the key log line is the engine\'s').toBe(String(w.keyLogLine).replace(/\s+/g, '').toLowerCase());
});

test('[A19.ui.tls11-schedule-key-labelled-public] the TLS 1.1 schedule names its key as the built-in training key, public in the source', async ({ page }) => {
  const w = await walk('/api/walk/tls11/schedule');
  expect(w.keySource, 'the engine runs on the built-in training key').toBe('training');
  await openWalk(page, 'walk-item-tls11', 'tls11-schedule-panel');
  const label = page.getByTestId('tls11-key-source');
  await expect(label, 'the screen labels its key').toBeVisible();
  expect(await label.getAttribute('data-key-source'), 'the label carries the engine\'s keySource').toBe('training');
  const words = ((await label.innerText()) ?? '').toLowerCase();
  expect(words.includes('training') && words.includes('public'), `the label names a public training key, and reads "${words}"`).toBe(true);
});

test('[A19.ui.tls11-schedule-open-with-show-keys-off] with Show keys OFF the TLS 1.1 schedule still shows its values', async ({ page }) => {
  await walk('/api/walk/tls11/schedule');
  await setShowKeys(false);
  try {
    const off = await walk('/api/walk/tls11/schedule');
    await openWalk(page, 'walk-item-tls11', 'tls11-schedule-panel');
    await tls11Values(page, off);
  } finally {
    await setShowKeys(true);
  }
});
