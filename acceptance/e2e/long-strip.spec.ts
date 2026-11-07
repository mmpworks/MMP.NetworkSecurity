import { test, expect, Page } from '@playwright/test';
import { openApp, requireLive, readState, HOST_PORT, TOKEN, NotRun } from './support';

/**
 * R1, "the long text is always visible" (docs/sections-plan.md lines 24, 107 and 112; Q3, Steve: A). In Techniques a pinned strip sits across
 * the top of the workspace, as a sibling above walk-root and outside it. It shows one mono line of the long cleartext, the current block
 * highlighted, and it scrolls sideways so the walk's chosen block stays in view. It stays while the learner moves between the Techniques items.
 * It is 44 px high, so 1280 x 640 still fits the walk. It reads the rows of POST /api/walk/aes/long-text, and it shows with Show keys OFF.
 * Test ids (this clause sets them): aes-long-strip on the strip, aes-long-block-{n} on each block, data-current="true" on the highlighted one.
 * Where the AES walk opens and the strip is missing, these clauses FAIL. They read NOT RUN only when Techniques has no AES walk at all.
 */

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
  if ((await section.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the top bar has no section-techniques');
  await section.click();
  const item = page.getByTestId('walk-item-aes');
  if ((await item.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the Techniques rail has no walk-item-aes');
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
