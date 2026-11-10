import { test, expect, Page } from '@playwright/test';
import { openApp, requireLive, readState, HOST_PORT, TOKEN, NotRun, controlMissing } from './support';

/**
 * R1, "the long text is always visible" (docs/sections-plan.md lines 24, 107 and 112; Q3, Steve: A). In Techniques a pinned strip sits across
 * the top of the workspace, as a sibling above walk-root and outside it. It shows one mono line of the long cleartext, the current block
 * highlighted, and it scrolls sideways so the walk's chosen block stays in view. It stays while the learner moves between the Techniques items.
 * It is 44 px high, so 1280 x 640 still fits the walk. It reads the rows of POST /api/walk/aes/long-text, and it shows with Show keys OFF.
 * A walk that shows a value derived from the text draws a link line from the strip to its grid (line 107).
 * Test ids (these clauses set them): aes-long-strip on the strip, aes-long-block-{n} on each block, data-current="true" on the highlighted one,
 * and aes-long-link on the link line, with data-from naming the strip block it starts from.
 * Where the AES walk opens and the strip is missing, these clauses FAIL. They read NOT RUN only when Techniques has no AES walk at all.
 */

// The Origin is the built-in http://localhost:5173, which the Host allows with or without NETSEC_ORIGINS (#225). If the built-in list ever
// drops it, this helper fails for a harness reason, and not because the strip is wrong.
async function setShowKeys(on: boolean): Promise<void> {
  const live = readState();
  if (!live.hostUp || !live.previewUp) return;
  const r = await fetch(`http://127.0.0.1:${HOST_PORT}/api/security/show-keys`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}`, Origin: 'http://localhost:5173' }, body: JSON.stringify({ on }),
  });
  expect(r.ok, 'PUT show-keys').toBe(true);
}

/** Opens Techniques, then its AES item. Returns once walk-root shows. No AES walk in Techniques reads NOT RUN. */
async function openAesTechnique(page: Page): Promise<void> {
  await openApp(page);
  const section = page.getByTestId('section-techniques');
  if ((await section.count()) === 0) throw controlMissing('section-techniques', 'the top bar has no section-techniques');
  await section.click();
  const item = page.getByTestId('walk-item-aes');
  if ((await item.count()) === 0) throw controlMissing('walk-item-aes', 'the Techniques rail has no walk-item-aes');
  await item.click();
  await expect(page.getByTestId('walk-root'), 'the AES walk opens in walk-root').toBeVisible({ timeout: 30_000 });
}

test('[A19.ui.long-strip-pinned-above-walk-root] the long-text strip sits above walk-root, outside it, 44 px high, and stays across the Techniques items', async ({ page }) => {
  requireLive();
  await page.setViewportSize({ width: 1280, height: 640 });
  await openAesTechnique(page);
  const strip = page.getByTestId('aes-long-strip');
  await expect(strip, 'Techniques shows the long-text strip (R1)').toBeVisible({ timeout: 15_000 });

  // A sibling above walk-root inside workspace, and never inside walk-root, so the walk's clip cannot cut it.
  const placement = await page.evaluate(() => {
    const s = document.querySelector('[data-testid="aes-long-strip"]');
    const w = document.querySelector('[data-testid="walk-root"]');
    const ws = document.querySelector('[data-testid="workspace"]');
    if (!s || !w || !ws) return { ok: false, why: 'strip, walk-root or workspace is missing' };
    if (w.contains(s)) return { ok: false, why: 'the strip is inside walk-root' };
    if (s.parentElement !== w.parentElement) return { ok: false, why: 'the strip and walk-root have different parents' };
    if (!ws.contains(s)) return { ok: false, why: 'the strip is outside workspace' };
    const before = !!(s.compareDocumentPosition(w) & Node.DOCUMENT_POSITION_FOLLOWING);
    return { ok: before, why: before ? '' : 'the strip comes after walk-root' };
  });
  expect(placement.ok, placement.why).toBe(true);

  const sb = await strip.boundingBox(), wb = await page.getByTestId('walk-root').boundingBox();
  expect(sb, 'the strip has a box').not.toBeNull();
  expect(Math.abs(sb!.height - 44), `the strip is 44 px high, and is ${sb!.height}`).toBeLessThanOrEqual(1);
  expect(wb!.y, 'walk-root starts below the strip').toBeGreaterThanOrEqual(sb!.y + sb!.height - 1);
  expect(wb!.y, 'at 1280 x 640, walk-root starts on screen').toBeLessThan(640);

  // It stays while the learner moves between the Techniques items.
  for (const other of ['hmac', 'dh', 'aes']) {
    await page.getByTestId(`walk-item-${other}`).click();
    await expect(strip, `the strip stays after picking ${other}`).toBeVisible({ timeout: 5_000 });
  }
});

test('[A19.ui.long-strip-shows-long-text-rows] the strip shows one block per row of POST /api/walk/aes/long-text, one current and in view, with Show keys OFF', async ({ page }) => {
  requireLive();
  try {
    await setShowKeys(false);
    const longText = page.waitForResponse(r => r.url().includes('/api/walk/aes/long-text') && r.request().method() === 'POST', { timeout: 30_000 }).catch(() => null);
    await openAesTechnique(page);
    const strip = page.getByTestId('aes-long-strip');
    await expect(strip, 'with Show keys OFF, Techniques still shows the long-text strip').toBeVisible({ timeout: 15_000 });
    const reply = await longText;
    expect(reply, 'the strip reads POST /api/walk/aes/long-text').not.toBeNull();
    expect(reply!.ok(), 'POST /api/walk/aes/long-text answers with Show keys OFF').toBe(true);
    const body = await reply!.json();
    const rows: any[] = Array.isArray(body?.rows) ? body.rows : [];
    expect(rows.length, 'the long-text reply holds rows').toBeGreaterThan(0);

    const blocks = page.locator('[data-testid^="aes-long-block-"]');
    expect(await blocks.count(), 'one strip block per row of the reply').toBe(rows.length);
    for (let n = 0; n < rows.length; n++) await expect(page.getByTestId(`aes-long-block-${n}`), `block ${n} has its id`).toHaveCount(1);
    const current = page.locator('[data-testid^="aes-long-block-"][data-current="true"]');
    expect(await current.count(), 'exactly one block is current').toBe(1);

    // One mono line that scrolls sideways, and the current block stays in view.
    const look = await strip.evaluate(el => { const cs = getComputedStyle(el); return { wrap: cs.whiteSpace, overflowX: cs.overflowX, font: cs.fontFamily }; });
    expect(look.wrap, 'one line: the strip does not wrap').toBe('nowrap');
    expect(['auto', 'scroll'], 'the strip scrolls sideways').toContain(look.overflowX);
    expect(look.font.toLowerCase(), 'the strip is mono').toMatch(/mono|courier|consolas|menlo/);
    const sb = await strip.boundingBox(), cb = await current.first().boundingBox();
    expect(cb!.x >= sb!.x - 1 && cb!.x + cb!.width <= sb!.x + sb!.width + 1, 'the current block is in the strip\'s view').toBe(true);
  } finally {
    await setShowKeys(true);
  }
});

test('[A19.ui.long-strip-links-to-the-walk-grid] when the walk shows a value from the text, a link line runs from the current strip block to the state grid', async ({ page }) => {
  requireLive();
  // State cells show only with Show keys ON. Set it here, so this clause does not depend on the order the clauses run in.
  await setShowKeys(true);
  await page.setViewportSize({ width: 1280, height: 800 });
  await openAesTechnique(page);
  const strip = page.getByTestId('aes-long-strip');
  await expect(strip, 'Techniques shows the long-text strip (R1)').toBeVisible({ timeout: 15_000 });

  // The first view starts on an empty grid, and each Next adds one byte of the block (CONTRACT.md, aes-walk-first-view). Step until a state cell shows.
  const cells = page.locator('[data-testid^="aes-walk-cell-"]');
  const next = page.getByTestId('aes-walk-next');
  for (let i = 0; i < 20 && (await cells.count()) === 0; i++) {
    if ((await next.count()) === 0 || !(await next.isEnabled())) break;
    await next.click();
  }
  expect(await cells.count(), 'the walk shows a state cell, so it shows a value derived from the text').toBeGreaterThan(0);

  const link = page.getByTestId('aes-long-link');
  await expect(link, 'a link line runs from the strip to the walk grid (sections-plan.md line 107)').toBeVisible({ timeout: 10_000 });
  const current = page.locator('[data-testid^="aes-long-block-"][data-current="true"]');
  expect(await current.count(), 'exactly one strip block is current').toBe(1);
  const from = await link.getAttribute('data-from');
  expect(from, 'the link names the current strip block in data-from').toBe(await current.first().getAttribute('data-testid'));

  // Its box reaches from the strip down to the state grid, and overlaps the current block across.
  const lb = await link.boundingBox(), sb = await strip.boundingBox(), cb = await current.first().boundingBox(), gb = await cells.first().boundingBox();
  expect(lb && sb && cb && gb, 'the link, the strip, the current block and a state cell each have a box').toBeTruthy();
  expect(lb!.y, 'the link starts at the strip').toBeLessThanOrEqual(sb!.y + sb!.height + 2);
  expect(lb!.y + lb!.height, 'the link reaches the state grid').toBeGreaterThanOrEqual(gb!.y - 2);
  expect(lb!.x <= cb!.x + cb!.width && lb!.x + lb!.width >= cb!.x, 'the link overlaps the current block across').toBe(true);

  // An item that shows no walk value draws no link.
  await page.getByTestId('walk-item-hmac').click();
  await expect(link, 'no link while the picked item shows no walk value').toHaveCount(0, { timeout: 5_000 });
});
