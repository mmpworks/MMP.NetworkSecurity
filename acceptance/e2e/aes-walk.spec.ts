import { expect, test, type Page } from '@playwright/test';
import { HOST_PORT, NotRun, TOKEN, hostGet, openApp, readState, requireLive } from './support';

/**
 * A19, chapter 1 of the AES walk in the app (docs/walkthrough-design.md sections 2.2, 2.3, 3.5, slice W1b). Test ids: CONTRACT.md section 6.
 * The Host clauses judge the bytes against RefAes and FIPS 197. These clauses judge what the screen does with those bytes, and read them from the Host's own reply.
 */

// The tour walk to the tab, and a clause that reads all 80 states, each take longer than the suite's 60 s default.
test.describe.configure({ timeout: 240_000 });
// An action with no bound waits out the whole test and reports only "test timeout". With this bound, the failure names the action.
test.use({ actionTimeout: 15_000 });

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
  // With no live Host of this run's own, a finally block must not hide the NOT RUN, and must not change another run's Host.
  const live = readState();
  if (!live.hostUp || !live.previewUp) return;
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
  const tab = page.getByTestId('aes-walk-tab');
  const next = page.getByTestId('tour-next');
  // A cold first page draws the button late. A check with no wait misses it, and then no tour runs, so every later look at Next waits out its bound.
  await expect(start.or(next).first(), 'the tour panel').toBeVisible({ timeout: 30_000 });
  if (await start.isVisible().catch(() => false)) await start.click();
  for (let hop = 0; hop < 30 && !(await tab.isVisible().catch(() => false)); hop++) {
    if (!(await next.isEnabled().catch(() => false))) { await page.waitForTimeout(1_000); continue; }
    await next.click().catch(() => { /* the tour moved on, or a step holds Next: the loop looks again */ });
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

/** Under reduced motion each step lands at once on its end frame, so a clause reads end frames and never waits on a timer (design section 2.2a). */
async function reduced(page: Page): Promise<void> { await page.emulateMedia({ reducedMotion: 'reduce' }); }

const running = (page: Page) => page.evaluate(() => document.getAnimations().filter(a => a.playState === 'running').length);

test('[A19.ui.end-frames-on-all-key-sizes] each step lands on the engine state, for 128, 192 and 256 bits', async ({ page }) => {
  await reduced(page);
  let reply = await openWalk(page);
  for (const bits of [128, 192, 256]) {
    if (bits !== 128) {
      const pick = page.getByTestId(`aes-walk-key-size-${bits}`);
      if (!(await pick.isVisible().catch(() => false))) throw new NotRun('PRODUCT_MISSING', `no aes-walk-key-size-${bits}. Key sizes arrive in W1c`);
      const [r] = await Promise.all([page.waitForResponse(WALK_BLOCK, { timeout: 30_000 }), pick.click()]);
      expect(r.status(), `GET block at ${bits} bits`).toBe(200);
      reply = await r.json();
      expect(reply.keyBits, 'the reply names the key size').toBe(bits);
    }
    await toFirstStep(page);
    const steps: any[] = [...reply.forward.steps, ...reply.inverse.steps];
    for (let i = 0; i < steps.length; i++) {
      expect(await grid(page), `${bits} bits, step ${i + 1} of ${steps.length} (${steps[i].kind})`).toBe(steps[i].state.toLowerCase());
      if (i < steps.length - 1) await page.getByTestId('aes-walk-next').click();
    }
  }
});

test('[A19.ui.reduced-motion-has-no-transition] with reduced motion each step shows its end frame, and nothing moves', async ({ page }) => {
  await reduced(page);
  const reply = await openWalk(page);
  await toFirstStep(page);
  const steps: any[] = [...reply.forward.steps, ...reply.inverse.steps];
  for (let i = 0; i < 12; i++) {
    await page.getByTestId('aes-walk-next').click();
    expect(await running(page), `running animations at step ${i + 2}`).toBe(0);
    expect(await grid(page), `the end frame at step ${i + 2}`).toBe(steps[i + 1].state.toLowerCase());
  }
  // The control: with motion allowed, a step does move. Design 2.2a: a click during a motion jumps to that step's end frame, and does not start the next step.
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.getByTestId('aes-walk-next').click();
  await expect.poll(() => running(page), { message: 'something moves with motion allowed', timeout: 2_000, intervals: [20] }).toBeGreaterThan(0);
  await page.getByTestId('aes-walk-next').click();
  await expect.poll(() => grid(page), { message: 'a click during a motion lands on that step\'s end frame', timeout: 5_000 }).toBe(steps[13].state.toLowerCase());
  await expect.poll(() => running(page), { message: 'the motion has ended', timeout: 5_000 }).toBe(0);
  expect(await grid(page), 'the click did not start the next step').toBe(steps[13].state.toLowerCase());
});

test('[A19.ui.play-stops-at-the-end-of-a-round] one Play and Pause button runs one round and stops, and pressing it again runs the next', async ({ page }) => {
  await reduced(page);
  const reply = await openWalk(page);
  await toFirstStep(page);
  const speed = page.getByTestId('aes-walk-speed');
  await expect(speed, 'the one speed control').toBeVisible();
  for (const name of ['slow', 'normal', 'fast']) await expect(speed.getByRole('radio', { name }).or(speed.getByRole('option', { name })).or(speed.getByRole('button', { name })).first(), `speed ${name}`).toBeAttached();
  const play = page.getByTestId('aes-walk-play');
  await expect(page.getByTestId('aes-walk-play-round'), 'no separate Play this round button').toHaveCount(0);
  const lastOfRound = (r: number) => reply.forward.steps.find((s: any) => s.kind === 'AddRoundKey' && s.round === r);
  for (const round of [1, 2]) {
    await play.click();
    await expect.poll(async () => await kindNow(page) === 'AddRoundKey' && (await grid(page)) === lastOfRound(round).state.toLowerCase(), { message: `Play stops at the end of round ${round}`, timeout: 15_000 }).toBe(true);
    const held = await grid(page);
    await page.waitForTimeout(800);
    expect(await grid(page), `the walk holds at the end of round ${round}`).toBe(held);
  }
});

test('[A19.ui.flip-during-play-stops-the-timeline] a flip to OFF during Play stops the motion and clears the walk', async ({ page }) => {
  try {
    await openWalk(page);
    await toFirstStep(page);
    await page.getByTestId('aes-walk-play').click();
    await page.getByTestId('show-keys-switch').click();
    await expect(page.locator('[data-testid^="aes-walk-cell-"]'), 'no state cell after the flip').toHaveCount(0, { timeout: 5_000 });
    await expect(page.getByTestId('aes-walk-closed')).toBeVisible();
    await page.waitForTimeout(800);
    await expect(page.locator('[data-testid^="aes-walk-cell-"]'), 'the timeline stays stopped').toHaveCount(0);
  } finally { await setShowKeys(true); }
});

const tableCell = (page: Page, n: number) => page.getByTestId(`aes-walk-table-cell-${n}`);

/** The whole expanded key as hex, from the reply's word rows, by the layout of design section 2.2b. */
const expandedHex = (rows: any[]) => rows.slice().sort((a, b) => a.i - b.i).map(r => r.word.toLowerCase()).join('');

/** A cell's byte, from data-hex, which is empty or absent until the cell is built. Cell text also holds a position mark and a word name, so the clause does not read text. */
async function hexOf(page: Page, n: number): Promise<string> { return ((await tableCell(page, n).getAttribute('data-hex')) ?? '').toLowerCase(); }

async function toKeySchedule(page: Page): Promise<void> {
  for (let i = 0; i < 40 && !(await tableCell(page, 0).isVisible().catch(() => false)); i++) await page.getByTestId('aes-walk-next').click();
  await expect(tableCell(page, 0), 'the expanded table').toBeVisible();
}

test('[A19.ui.expanded-table-layout] 11 grids of 16 cells: the key cells start filled, and each cell names its word and shows no letter', async ({ page }) => {
  const reply = await openWalk(page);
  await toKeySchedule(page);
  const hex = expandedHex(reply.keyWords);
  await expect(page.locator('[data-testid^="aes-walk-table-grid-"]'), 'one grid per round key').toHaveCount(11);
  await expect(page.locator('[data-testid^="aes-walk-table-cell-"]'), 'one cell per byte, 0 to 175').toHaveCount(176);
  await expect(page.getByTestId('aes-walk-table-grid-1').locator('[data-testid^="aes-walk-table-cell-"]'), 'each grid holds 16 cells').toHaveCount(16);
  for (let n = 0; n < 176; n++) {
    const c = tableCell(page, n);
    await expect(c, `byte ${n}: its word name`).toHaveAttribute('data-word', `w${Math.floor(n / 4)}`);
    expect(await c.getAttribute('data-letter'), `byte ${n}: key bytes are not text`).toBeNull();
    if (n < 16) expect(await hexOf(page, n), `key byte ${n} starts filled`).toBe(hex.slice(2 * n, 2 * n + 2));
    else expect(await hexOf(page, n), `byte ${n} starts empty`).toBe('');
  }
});

test('[A19.ui.word-build-lights-its-two-words] Next adds one word, the lit cells hold its two source words, and a tap opens only a built word', async ({ page }) => {
  const reply = await openWalk(page);
  await toKeySchedule(page);
  const tables = await hostGet('/api/walk/aes/tables');
  expect(tables.status, 'GET tables').toBe(200);
  const rcon: string = tables.body.rcon;
  const shown = ((await page.getByTestId('aes-walk-rcon').textContent()) ?? '').replace(/\s+/g, '').toLowerCase();
  expect(shown, 'the Rcon row comes from the Host').toContain(rcon.toLowerCase());
  const rows: any[] = reply.keyWords.slice().sort((a: any, b: any) => a.i - b.i);
  const nk = tables.body.sizes.find((s: any) => s.keyBits === reply.keyBits).keyWords;
  const hex = expandedHex(rows);
  /** Every lit cell, as word name to its bytes in position order. So lighting extra cells, or the wrong cells, fails. */
  const litWords = async () => {
    const lit = page.locator('[data-testid^="aes-walk-table-cell-"][data-lit="true"]');
    const words: Record<string, string> = {};
    for (let k = 0; k < await lit.count(); k++) {
      const name = (await lit.nth(k).getAttribute('data-word')) ?? '?';
      words[name] = (words[name] ?? '') + ((await lit.nth(k).getAttribute('data-hex')) ?? '').toLowerCase();
    }
    return words;
  };
  // A tap on a word not yet built does nothing.
  await tableCell(page, 4 * 10).click();
  await expect(page.getByTestId('aes-walk-build-word'), 'an unbuilt word opens no stage rows').toHaveCount(0);
  // A key word has no stage rows, and says so.
  await tableCell(page, 0).click();
  await expect(page.getByTestId('aes-walk-build-key-note')).toContainText('This word is part of the key');
  for (const i of [nk, nk + 1, nk + 2, nk + 3, nk + 4]) {
    const row = rows.find(r => r.i === i);
    await page.getByTestId('aes-walk-next').click();
    for (let b = 0; b < 4; b++) expect(await hexOf(page, 4 * i + b), `w${i} byte ${b} is built`).toBe(hex.slice(2 * (4 * i + b), 2 * (4 * i + b) + 2));
    expect(await hexOf(page, 4 * (i + 1)), `w${i + 1} is not built yet`).toBe('');
    expect(await litWords(), `w${i}: only its two source words are lit`).toEqual({ [`w${i - 1}`]: row.previous.toLowerCase(), [`w${i - nk}`]: row.keyBack.toLowerCase() });
  }
  await tableCell(page, 4 * nk).click();
  const row = rows.find(r => r.i === nk);
  for (const [id, value] of [['previous', row.previous], ['rotated', row.rotated], ['substituted', row.substituted], ['rcon', row.rcon], ['after-rcon', row.afterRcon], ['key-back', row.keyBack], ['word', row.word]])
    await expect(page.getByTestId(`aes-walk-build-${id}`), `the stage rows of w${nk}: ${id}`).toContainText(value, { ignoreCase: true });
});

test('[A19.ui.key-band-on-192-and-256] at 192 and 256 bits the key runs past round key 0, the key cells start filled, and the panel says how many words', async ({ page }) => {
  await openWalk(page);
  for (const [bits, grids, cells, nk] of [[192, 13, 208, 6], [256, 15, 240, 8]]) {
    const pick = page.getByTestId(`aes-walk-key-size-${bits}`);
    if (!(await pick.isVisible().catch(() => false))) throw new NotRun('PRODUCT_MISSING', `no aes-walk-key-size-${bits}. Key sizes arrive in W1c`);
    const [r] = await Promise.all([page.waitForResponse(WALK_BLOCK, { timeout: 30_000 }), pick.click()]);
    const reply = await r.json();
    await toKeySchedule(page);
    await expect(page.locator('[data-testid^="aes-walk-table-grid-"]'), `${bits} bits: grids`).toHaveCount(grids);
    await expect(page.locator('[data-testid^="aes-walk-table-cell-"]'), `${bits} bits: cells`).toHaveCount(cells);
    const hex = expandedHex(reply.keyWords);
    for (let n = 0; n < 4 * nk; n++) {
      expect(await hexOf(page, n), `${bits} bits: key byte ${n} starts filled`).toBe(hex.slice(2 * n, 2 * n + 2));
      await expect(tableCell(page, n), `${bits} bits: key byte ${n} is in the band`).toHaveAttribute('data-key', 'true');
    }
    await expect(tableCell(page, 4 * nk), `${bits} bits: the first built word is past the band`).not.toHaveAttribute('data-key', 'true');
    await expect(page.getByTestId('aes-walk-key-band-note'), `${bits} bits: the line`).toContainText(`first ${nk} words are the key`);
  }
});

test('[A19.ui.multiply-shows-the-engine-terms] the field panel states the definition, and a MixColumns step prints one real multiply from the reply', async ({ page }) => {
  const reply = await openWalk(page);
  await toFirstStep(page);
  for (let n = 0; n < 200 && (await kindNow(page)) !== 'MixColumns'; n++) await page.getByTestId('aes-walk-next').click();
  expect(await kindNow(page)).toBe('MixColumns');
  await expect(page.getByTestId('aes-walk-field-panel'), 'the definition').toContainText('Add is XOR.');
  const step = reply.forward.steps.find((s: any) => s.kind === 'MixColumns');
  await cell(page, 0, 0).click();
  const parts: any[] = step.terms[0].parts;
  for (let j = 0; j < 4; j++) {
    const t = page.getByTestId(`aes-walk-term-${j}`);
    await expect(t, `term ${j}: the input`).toContainText(parts[j].input, { ignoreCase: true });
    await expect(t, `term ${j}: the result`).toContainText(parts[j].result, { ignoreCase: true });
    await expect(t, `term ${j}: the factor`).toContainText(String(parts[j].factor));
    await expect(t, `term ${j}: whether it reduced`).toHaveAttribute('data-reduced', String(parts[j].reduced));
  }
  await expect(page.getByTestId('aes-walk-term-result'), 'the XOR of the terms').toContainText(step.terms[0].result, { ignoreCase: true });
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
