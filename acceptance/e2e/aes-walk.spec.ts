import { expect, test, type Page } from '@playwright/test';
import { HOST_PORT, NotRun, TOKEN, hostGet, openApp, requireLive } from './support';

/**
 * A19, chapter 1 of the AES walk in the app (docs/walkthrough-design.md sections 2.2, 2.3, 3.5, slice W1b). Test ids: CONTRACT.md section 6.
 * The Host clauses judge the bytes against RefAes and FIPS 197. These clauses judge what the screen does with those bytes, and read them from the Host's own reply.
 */

const TEXT = 'Pump four is ok.';
const WALK_BLOCK = /\/walk\/aes\/block/;

/** FIPS 197 sections 5.1 and 5.3, written out from the rule. No value comes from the app. */
function kindOrder(rounds: number, encrypt: boolean): string[] {
  const k = ['AddRoundKey'];
  for (let r = 1; r <= rounds; r++) {
    if (encrypt) { k.push('SubBytes', 'ShiftRows'); if (r < rounds) k.push('MixColumns'); k.push('AddRoundKey'); }
    else { k.push('InvShiftRows', 'InvSubBytes', 'AddRoundKey'); if (r < rounds) k.push('InvMixColumns'); }
  }
  return k;
}

async function setShowKeys(on: boolean): Promise<void> {
  const r = await fetch(`http://127.0.0.1:${HOST_PORT}/api/security/show-keys`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}`, Origin: 'http://localhost:5173' }, body: JSON.stringify({ on }),
  });
  expect(r.ok, 'PUT show-keys').toBe(true);
}

/** Runs lesson 1 with the tour's Next until the run holds aes.key and the tab shows. A build with no tab reads NOT RUN, never PASS. */
async function reachTab(page: Page): Promise<void> {
  requireLive();
  // Design section 2.2a: under reduced motion each step lands at once on its end frame, so no clause reads a cell inside a motion.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await openApp(page);
  await page.getByTestId('lesson-item-1').click();
  const start = page.getByRole('button', { name: /start tour/i });
  if (await start.isVisible().catch(() => false)) await start.click();
  const tab = page.getByTestId('aes-walk-tab');
  const next = page.getByTestId('tour-next');
  for (let hop = 0; hop < 30 && !(await tab.isVisible().catch(() => false)); hop++) {
    if (!(await next.isEnabled().catch(() => false))) { await page.waitForTimeout(1_000); continue; }
    await next.click();
    await page.waitForTimeout(500);
  }
  if (!(await tab.isVisible().catch(() => false))) throw new NotRun('PRODUCT_MISSING', 'lesson 1 shows no aes-walk-tab');
}

async function openWalk(page: Page): Promise<any> {
  await reachTab(page);
  const [reply] = await Promise.all([page.waitForResponse(WALK_BLOCK, { timeout: 30_000 }), page.getByTestId('aes-walk-tab').click()]);
  expect(reply.status(), 'GET block').toBe(200);
  await expect(page.getByTestId('aes-walk-panel')).toBeVisible({ timeout: 15_000 });
  return await reply.json();
}

const cell = (page: Page, r: number, c: number) => page.getByTestId(`aes-walk-cell-${r}-${c}`);

/** The byte in each cell, read by row and column and put back in FIPS order: position r + 4c. */
async function grid(page: Page): Promise<string> {
  const out: string[] = new Array(16).fill('');
  for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) out[r + 4 * c] = ((await cell(page, r, c).textContent()) ?? '').trim().slice(0, 2).toLowerCase();
  return out.join('');
}

async function kindNow(page: Page): Promise<string> { return ((await page.getByTestId('aes-walk-step-kind').textContent()) ?? '').trim(); }

async function nextEnabled(page: Page): Promise<boolean> { return await page.getByTestId('aes-walk-next').isEnabled().catch(() => false); }

/** Moves past the first view and the key rows, to the first state of the encrypt run. */
async function toFirstStep(page: Page): Promise<void> {
  for (let i = 0; i < 200 && (await kindNow(page)) !== 'AddRoundKey'; i++) {
    expect(await nextEnabled(page), 'Next is on while the first step is not reached').toBe(true);
    await page.getByTestId('aes-walk-next').click();
  }
}

test('[A19.ui.first-view-fills-by-column] block 1 drops in one byte at a time, down the first column, and the first column reads Pump', async ({ page }) => {
  const reply = await openWalk(page);
  await expect(page.getByTestId('aes-walk-first-view')).toBeVisible();
  for (let pos = 0; pos < 16; pos++) {
    const r = pos % 4, c = Math.floor(pos / 4);
    await page.getByTestId('aes-walk-next').click();
    await expect(cell(page, r, c), `position ${pos} is at row ${r}, column ${c}`).toContainText(reply.inputHex.slice(2 * pos, 2 * pos + 2), { ignoreCase: true });
    if (pos < 15) await expect(cell(page, (pos + 1) % 4, Math.floor((pos + 1) / 4)), `position ${pos + 1} is still empty`).toHaveText(/^\s*$|^\s*\d+\s*$/);
  }
  const letters: string[] = [];
  for (let row = 0; row < 4; row++) letters.push(((await cell(page, row, 0).getAttribute('data-letter')) ?? ''));
  expect(letters.join(''), 'the first column reads').toBe('Pump');
  const top: string[] = [];
  for (let col = 0; col < 4; col++) top.push(((await cell(page, 0, col).getAttribute('data-letter')) ?? ''));
  expect(top.join(''), 'the top row reads').toBe('P r ');
});

test('[A19.ui.grid-order-on-every-state] on each state of both runs, row r, column c shows byte r + 4c of the reply', async ({ page }) => {
  const reply = await openWalk(page);
  await toFirstStep(page);
  const steps: any[] = [...reply.forward.steps, ...reply.inverse.steps];
  for (let i = 0; i < steps.length; i++) {
    expect(await grid(page), `step ${i + 1} of ${steps.length} (${steps[i].kind})`).toBe(steps[i].state.toLowerCase());
    if (i < steps.length - 1) await page.getByTestId('aes-walk-next').click();
  }
});

test('[A19.ui.step-order-by-next] Next alone meets the FIPS 197 steps in order, for encrypt and then decrypt', async ({ page }) => {
  const reply = await openWalk(page);
  await toFirstStep(page);
  const want = [...kindOrder(reply.rounds, true), ...kindOrder(reply.rounds, false)];
  for (let i = 0; i < want.length; i++) {
    expect(await kindNow(page), `step ${i + 1} of ${want.length}`).toBe(want[i]);
    if (i < want.length - 1) await page.getByTestId('aes-walk-next').click();
  }
});

test('[A19.ui.next-alone-gives-the-text-back] a learner reaches the text by Next alone, and Back returns one step', async ({ page }) => {
  await openWalk(page);
  await toFirstStep(page);
  const before = await grid(page);
  await page.getByTestId('aes-walk-next').click();
  await page.getByTestId('aes-walk-back').click();
  expect(await grid(page), 'Back returns to the step before').toBe(before);
  let clicks = 0;
  while (await nextEnabled(page)) { await page.getByTestId('aes-walk-next').click(); expect(++clicks, 'the walk ends').toBeLessThan(200); }
  await expect(page.getByTestId('aes-walk-readable')).toHaveText(TEXT);
});

/** On a substitution step: each clicked cell lights a row and a column of the table, and the table's value there equals that cell's next state. */
async function checkLookups(page: Page, table: string, kind: string, steps: any[]): Promise<void> {
  const i = steps.findIndex(s => s.kind === kind);
  expect(i, `the run has a ${kind} step`).toBeGreaterThan(0);
  const before: string = steps[i - 1].state, after: string = steps[i].state;
  for (let p = 0; p < 16; p++) {
    const r = p % 4, c = Math.floor(p / 4);
    const byte = before.slice(2 * p, 2 * p + 2), value = after.slice(2 * p, 2 * p + 2);
    await cell(page, r, c).click();
    await expect(page.getByTestId('aes-walk-sbox-row'), `cell ${p}: the row`).toHaveText(byte[0], { ignoreCase: true });
    await expect(page.getByTestId('aes-walk-sbox-col'), `cell ${p}: the column`).toHaveText(byte[1], { ignoreCase: true });
    await expect(page.getByTestId('aes-walk-sbox-value'), `cell ${p}: the value`).toHaveText(value, { ignoreCase: true });
    const x = parseInt(byte[0], 16), y = parseInt(byte[1], 16);
    await expect(page.getByTestId(`aes-walk-sbox-cell-${byte[0]}-${byte[1]}`), `cell ${p}: the table cell`).toHaveText(table.slice(2 * (16 * x + y), 2 * (16 * x + y) + 2), { ignoreCase: true });
    expect(value, `cell ${p}: FIPS table lookup equals the next state`).toBe(table.slice(2 * (16 * x + y), 2 * (16 * x + y) + 2));
  }
}

test('[A19.ui.sbox-click-matches-next-state] a clicked cell lights its row and column, and the lookup equals the next state, on both tables', async ({ page }) => {
  const reply = await openWalk(page);
  const tables = await hostGet('/api/walk/aes/tables');
  expect(tables.status, 'GET tables').toBe(200);
  await toFirstStep(page);
  const go = async (kind: string) => {
    for (let n = 0; n < 200 && (await kindNow(page)) !== kind; n++) await page.getByTestId('aes-walk-next').click();
    expect(await kindNow(page)).toBe(kind);
  };
  await go('SubBytes');
  await checkLookups(page, tables.body.sbox.toLowerCase(), 'SubBytes', reply.forward.steps);
  await go('InvSubBytes');
  await checkLookups(page, tables.body.inverseSbox.toLowerCase(), 'InvSubBytes', reply.inverse.steps);
});

test('[A19.ui.off-shows-the-closed-line] with Show keys OFF the steps close, the line says why, and the table stays open', async ({ page }) => {
  try {
    await reachTab(page);
    await setShowKeys(false);
    await page.reload();
    await reachTab(page);
    await page.getByTestId('aes-walk-tab').click();
    await expect(page.getByTestId('aes-walk-closed')).toContainText('Show keys is off');
    await expect(page.getByTestId('aes-walk-closed')).toContainText('modes walk stay open');
    await expect(page.locator('[data-testid^="aes-walk-cell-"]'), 'no state cell while closed').toHaveCount(0);
    expect((await hostGet('/api/walk/aes/tables')).status, 'the tables route').toBe(200);
  } finally { await setShowKeys(true); }
});

test('[A19.ui.flip-clears-with-the-frame-dropped] the walk clears when the switch goes OFF, with the flip frame dropped on purpose', async ({ page }) => {
  try {
    await page.routeWebSocket(/.*/, ws => {
      const server = ws.connectToServer();
      server.onMessage(m => { if (!String(m).includes('security.show-keys')) ws.send(m); });
      ws.onMessage(m => server.send(m));
    });
    await openWalk(page);
    await toFirstStep(page);
    await page.getByTestId('show-keys-switch').click();
    await expect(page.locator('[data-testid^="aes-walk-cell-"]'), 'no state cell after the flip').toHaveCount(0, { timeout: 5_000 });
    await expect(page.getByTestId('aes-walk-closed')).toBeVisible();
  } finally { await setShowKeys(true); }
});

test('[A19.ui.socket-close-clears-the-walk] the walk clears when the socket closes', async ({ page }) => {
  const open: { close: () => Promise<void> }[] = [];
  await page.routeWebSocket(/.*/, ws => {
    const server = ws.connectToServer();
    server.onMessage(m => ws.send(m));
    ws.onMessage(m => server.send(m));
    open.push(ws);
  });
  await openWalk(page);
  await toFirstStep(page);
  expect(open.length, 'the app holds a socket').toBeGreaterThan(0);
  // After a reconnect the app may fetch again (the next clause). Aborting that fetch leaves only the clear to observe.
  await page.route(WALK_BLOCK, r => r.abort());
  await Promise.all(open.map(ws => ws.close()));
  await expect(page.locator('[data-testid^="aes-walk-cell-"]'), 'no state cell after the close').toHaveCount(0, { timeout: 5_000 });
});

test('[A19.ui.late-reply-is-dropped] a block reply that lands after the flip to OFF never reaches the screen', async ({ page }) => {
  try {
    await reachTab(page);
    let release = () => { /* set below */ };
    const held = new Promise<void>(res => { release = res; });
    let asked = false;
    await page.route(WALK_BLOCK, async route => {
      asked = true;
      const response = await route.fetch();
      await held;
      await route.fulfill({ response });
    });
    await page.getByTestId('aes-walk-tab').click();
    await expect.poll(() => asked, { message: 'the panel asks for the walk', timeout: 15_000 }).toBe(true);
    await page.getByTestId('show-keys-switch').click();
    await expect(page.getByTestId('aes-walk-closed')).toBeVisible();
    release();
    await page.waitForTimeout(1_500);
    await expect(page.locator('[data-testid^="aes-walk-cell-"]'), 'the late reply stays off the screen').toHaveCount(0);
    await expect(page.getByTestId('aes-walk-closed')).toBeVisible();
  } finally { await setShowKeys(true); }
});

test('[A19.ui.reconnect-reads-the-toggle-first] after a reconnect the app reads the toggle first, and fetches the walk only when it is ON', async ({ page }) => {
  try {
    const open: { close: () => Promise<void> }[] = [];
    let closing = false;
    await page.routeWebSocket(/.*/, ws => {
      const server = ws.connectToServer();
      server.onMessage(m => ws.send(m));
      ws.onMessage(m => server.send(m));
      if (!closing) open.push(ws);
    });
    await openWalk(page);
    await toFirstStep(page);
    let asksAfterClose = 0;
    page.on('request', q => { if (WALK_BLOCK.test(q.url())) asksAfterClose++; });
    await setShowKeys(false);
    closing = true;
    await Promise.all(open.map(ws => ws.close()));
    await expect(page.getByTestId('aes-walk-closed')).toBeVisible({ timeout: 30_000 });
    await page.waitForTimeout(2_000);
    expect(asksAfterClose, 'block requests after the reconnect, with Show keys OFF').toBe(0);
    await expect(page.locator('[data-testid^="aes-walk-cell-"]')).toHaveCount(0);
  } finally { await setShowKeys(true); }
});
