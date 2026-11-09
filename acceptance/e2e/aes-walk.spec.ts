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

/** The one step list, in Next order. Design 2.2a: after encrypt's last step, Next lands on the decrypt Start view, a stop with no motion, where the block equals forward.output. */
const DECRYPT_START = 'decrypt start view';
const stopsInOrder = (reply: any): any[] => [...reply.forward.steps, { kind: DECRYPT_START, state: reply.forward.output }, ...reply.inverse.steps];

const cell = (page: Page, r: number, c: number) => page.getByTestId(`aes-walk-cell-${r}-${c}`);

/** A block cell's byte: data-hex when the cell carries it (a cell that also shows its index and character), else the first 2 characters of its text. */
async function cellHex(page: Page, r: number, c: number): Promise<string> {
  const attr = await cell(page, r, c).getAttribute('data-hex');
  return (attr ?? ((await cell(page, r, c).textContent()) ?? '').trim().slice(0, 2)).toLowerCase();
}

/** The byte in each cell, read by row and column and put back in FIPS order: position r + 4c. */
async function grid(page: Page): Promise<string> {
  const out: string[] = new Array(16).fill('');
  for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) out[r + 4 * c] = await cellHex(page, r, c);
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
  const steps: any[] = stopsInOrder(reply);
  for (let i = 0; i < steps.length; i++) {
    expect(await grid(page), `step ${i + 1} of ${steps.length} (${steps[i].kind})`).toBe(steps[i].state.toLowerCase());
    if (i < steps.length - 1) await page.getByTestId('aes-walk-next').click();
  }
});

test('[A19.ui.step-order-by-next] Next alone meets the FIPS 197 steps in order, for encrypt and then decrypt', async ({ page }) => {
  const reply = await openWalk(page);
  await toFirstStep(page);
  const want = [...kindOrder(reply.rounds, true), DECRYPT_START, ...kindOrder(reply.rounds, false)];
  for (let i = 0; i < want.length; i++) {
    if (want[i] === DECRYPT_START) {
      // The stop holds no step of the cipher, so its label is another word. The block is what encrypt produced.
      expect(want.slice(0, i).concat(want.slice(i + 1)), 'the stop is not a cipher step').not.toContain(await kindNow(page));
      expect(await grid(page), 'the decrypt Start view holds forward.output').toBe(reply.forward.output.toLowerCase());
    } else expect(await kindNow(page), `step ${i + 1} of ${want.length}`).toBe(want[i]);
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
    const steps: any[] = stopsInOrder(reply);
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
  const steps: any[] = stopsInOrder(reply);
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

/*
 * Steve's AES walk fixes (2026-11-08), with the design mock at E:/dev/ns-mock/design/mock/ (template.html, keys_anim.js):
 * 1. a block cell shows its byte index and its letter;
 * 2. the key schedule builds a word step by step (RotWord, SubWord, Rcon, XOR with the word Nk back), with one color per role;
 * 3. the Key Schedule panel zooms in and out, with a reset, and nothing scrolls sideways at 1280 px wide;
 * 4. the landscape view: the round-key grid left and the "How wN is made" panel right at 1280 px and up, stacked below.
 * The letter line for a byte that is not printable follows the app's own long-text strip legend (walk-gloss.json, strip.legend:
 * "· is a byte that is not a printable character"), and a space shows "sp", as in the mock. The mock shows nothing for such a byte.
 */

/** The letter line of a byte. A byte that is not printable may show '.' or the middle dot of the strip legend, since both are a dot. */
function charOk(hex: string, shown: string): boolean {
  const n = parseInt(hex, 16);
  if (n === 0x20) return shown === 'sp';
  if (n > 0x20 && n < 0x7f) return shown === String.fromCharCode(n);
  return shown === '.' || shown === '\u00b7';
}

async function requireCellParts(page: Page): Promise<void> {
  if ((await page.getByTestId('aes-walk-cell-0-0-index').count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'block cells have no aes-walk-cell-{r}-{c}-index yet (Steve fix 1)');
}

/** The step panel's title, such as "How w4 is made". */
async function buildTitle(page: Page): Promise<string> { return ((await page.getByTestId('aes-walk-ks-build-title').textContent().catch(() => '')) ?? '').trim(); }

/** The 8 bits of a byte as the mock prints them: two nibbles, with an optional space between. */
function bitsRe(hex: string): string {
  const b = parseInt(hex, 16).toString(2).padStart(8, '0');
  return `${b.slice(0, 4)}\\s?${b.slice(4)}`;
}

/** Every cell's index and character line, against the 16 bytes the cells should hold ('' for an empty cell). */
async function checkCellParts(page: Page, hex16: string[], where: string): Promise<void> {
  for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) {
    const pos = r + 4 * c, h = hex16[pos];
    const index = ((await page.getByTestId(`aes-walk-cell-${r}-${c}-index`).textContent()) ?? '').trim();
    expect(index, `${where}: cell ${r},${c} shows its byte index`).toBe(String(pos));
    const ch = ((await page.getByTestId(`aes-walk-cell-${r}-${c}-char`).textContent().catch(() => '')) ?? '').trim();
    if (h === '') { expect(ch, `${where}: empty cell ${r},${c} shows no character`).toBe(''); continue; }
    expect(charOk(h, ch), `${where}: cell ${r},${c} holds ${h} and shows "${ch}"`).toBe(true);
    expect(await cellHex(page, r, c), `${where}: cell ${r},${c} still shows its hex`).toBe(h);
  }
}

const bytesOf = (hex: string) => Array.from({ length: 16 }, (_, i) => hex.slice(2 * i, 2 * i + 2).toLowerCase());
const printable = (h: string) => { const n = parseInt(h, 16); return n >= 0x20 && n < 0x7f; };

test('[A19.ui.block-cell-shows-index-and-char] each block cell shows its byte index and its character: "sp" for a space, a dot for a byte that is not printable', async ({ page }) => {
  const reply = await openWalk(page);
  await requireCellParts(page);
  await checkCellParts(page, new Array(16).fill(''), 'first view, nothing filled');
  for (let pos = 0; pos < 16; pos++) await page.getByTestId('aes-walk-next').click();
  // "Pump four is ok." holds letters, three spaces and a full stop. A space shows "sp".
  await checkCellParts(page, bytesOf(reply.inputHex), 'block 1 filled');
  await toFirstStep(page);
  // The first AddRoundKey state holds bytes that are not printable, so the dot rule is tested on real engine bytes.
  const state = bytesOf(reply.forward.steps[0].state);
  expect(state.some(h => !printable(h)), 'the first AddRoundKey state holds a byte that is not printable').toBe(true);
  await checkCellParts(page, state, 'first AddRoundKey');
});

/** The first time each watched element is seen, in ms from the start, sampled in the page once per frame. */
async function firstSeen(page: Page, ids: string[], hexCells: string[], ms: number): Promise<{ rows: Record<string, number>; cells: Record<string, number> }> {
  return await page.evaluate(({ ids, hexCells, ms }) => new Promise<{ rows: Record<string, number>; cells: Record<string, number> }>(done => {
    const rows: Record<string, number> = {}, cells: Record<string, number> = {};
    const t0 = performance.now();
    const visible = (el: Element | null) => !!el && (el as HTMLElement).offsetParent !== null && getComputedStyle(el).visibility !== 'hidden' && Number(getComputedStyle(el).opacity) > 0.5;
    const tick = () => {
      const t = performance.now() - t0;
      for (const id of ids) if (rows[id] === undefined && visible(document.querySelector(`[data-testid="${id}"]`))) rows[id] = t;
      for (const id of hexCells) if (cells[id] === undefined && (document.querySelector(`[data-testid="${id}"]`)?.getAttribute('data-hex') ?? '') !== '') cells[id] = t;
      if (t > ms || (Object.keys(rows).length === ids.length && Object.keys(cells).length === hexCells.length)) done({ rows, cells });
      else requestAnimationFrame(tick);
    };
    tick();
  }), { ids, hexCells, ms });
}

const STAGES = ['previous', 'rotated', 'substituted', 'rcon', 'after-rcon', 'key-back', 'word'];

test('[A19.ui.key-word-build-runs-in-steps] with motion on, Next on a RotWord word shows RotWord, SubWord, Rcon and the XOR with the word Nk back one after another, then fills the new word one byte at a time', async ({ page }) => {
  const reply = await openWalk(page);
  await toKeySchedule(page);
  const tables = await hostGet('/api/walk/aes/tables');
  const nk = tables.body.sizes.find((s: any) => s.keyBits === reply.keyBits).keyWords;
  const row = reply.keyWords.find((r: any) => r.i === nk);
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  const ids = STAGES.map(s => `aes-walk-build-${s}`);
  const newCells = [0, 1, 2, 3].map(b => `aes-walk-table-cell-${4 * nk + b}`);
  const [seen] = await Promise.all([firstSeen(page, ids, newCells, 20_000), page.getByTestId('aes-walk-next').click()]);
  const order = ids.map(id => seen.rows[id]);
  if (order.every(t => t === undefined)) throw new NotRun('UI_CONTROL_MISSING', `Next onto w${nk} showed no aes-walk-build-* row without a tap (Steve fix 2: the build runs by itself)`);
  ids.forEach(id => expect(seen.rows[id], `${id} appears during the build of w${nk}`).not.toBeUndefined());
  for (let k = 1; k < ids.length; k++) expect(order[k], `${ids[k]} appears after ${ids[k - 1]} (FIPS 197 order)`).toBeGreaterThanOrEqual(order[k - 1]);
  expect(order[ids.length - 1] - order[0], 'the stages come one after another, not in one frame').toBeGreaterThanOrEqual(300);
  const fills = newCells.map(id => seen.cells[id]);
  fills.forEach((t, b) => expect(t, `w${nk} byte ${b} is filled during the build`).not.toBeUndefined());
  for (let b = 1; b < 4; b++) expect(fills[b], `w${nk} byte ${b} fills after byte ${b - 1}`).toBeGreaterThan(fills[b - 1]);
  expect(fills[0], 'the new word fills after the stage rows begin').toBeGreaterThan(order[0]);
  // The end frame holds the engine's values, the same as with reduced motion.
  await expect.poll(() => running(page), { timeout: 20_000 }).toBe(0);
  for (const [id, value] of [['previous', row.previous], ['rotated', row.rotated], ['substituted', row.substituted], ['rcon', row.rcon], ['after-rcon', row.afterRcon], ['key-back', row.keyBack], ['word', row.word]])
    await expect(page.getByTestId(`aes-walk-build-${id}`), `end frame of w${nk}: ${id}`).toContainText(value, { ignoreCase: true });
  for (let b = 0; b < 4; b++) expect(await hexOf(page, 4 * nk + b), `w${nk} byte ${b} at the end`).toBe(row.word.slice(2 * b, 2 * b + 2).toLowerCase());
});

/** Every background color an element and the elements inside it show, as computed strings. */
const backgrounds = (page: Page, testid: string) => page.getByTestId(testid).evaluate(el => [el, ...Array.from(el.querySelectorAll('*'))].map(e => getComputedStyle(e).backgroundColor));

test('[A19.ui.key-roles-have-colors] the word being built, the word before it and the word Nk back each have a role color, the same in the table and in the stage rows', async ({ page }) => {
  const reply = await openWalk(page);
  await toKeySchedule(page);
  const tables = await hostGet('/api/walk/aes/tables');
  const nk = tables.body.sizes.find((s: any) => s.keyBits === reply.keyBits).keyWords;
  await page.getByTestId('aes-walk-next').click();
  const roleCell = (role: string) => page.locator(`[data-testid^="aes-walk-table-cell-"][data-role="${role}"]`);
  if ((await roleCell('new').count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'no aes-walk-table-cell-* carries data-role yet (Steve fix 2)');
  const words: Record<string, string> = { new: `w${nk}`, previous: `w${nk - 1}`, 'key-back': 'w0' };
  const color: Record<string, string> = {};
  for (const [role, word] of Object.entries(words)) {
    const cells = roleCell(role);
    expect(await cells.count(), `${role}: the 4 cells of ${word}`).toBe(4);
    const bgs = new Set<string>();
    for (let k = 0; k < 4; k++) {
      expect(await cells.nth(k).getAttribute('data-word'), `${role} cell ${k}`).toBe(word);
      bgs.add(await cells.nth(k).evaluate(e => getComputedStyle(e).backgroundColor));
    }
    expect(bgs.size, `${role}: one color on all 4 cells`).toBe(1);
    color[role] = [...bgs][0];
  }
  const plain = await tableCell(page, 4 * (nk + 5)).evaluate(e => getComputedStyle(e).backgroundColor);
  const roles = Object.keys(words);
  for (let a = 0; a < roles.length; a++) {
    expect(color[roles[a]], `${roles[a]} differs from a cell with no role`).not.toBe(plain);
    for (let b = a + 1; b < roles.length; b++) expect(color[roles[a]], `${roles[a]} and ${roles[b]} differ`).not.toBe(color[roles[b]]);
  }
  for (const [role, stage] of [['previous', 'previous'], ['key-back', 'key-back'], ['new', 'word']])
    expect(await backgrounds(page, `aes-walk-build-${stage}`), `the ${stage} stage row shows the ${role} color`).toContain(color[role]);
});

/** How far the page and the Key Schedule panel scroll sideways, in px. */
const sideScroll = (page: Page) => page.evaluate(() => {
  const d = document.documentElement, p = document.querySelector('[data-testid="aes-walk-key-schedule"]') as HTMLElement | null;
  return { page: d.scrollWidth - d.clientWidth, panel: p ? p.scrollWidth - p.clientWidth : 0 };
});

test('[A19.ui.key-schedule-zoom] at 1280 px the Key Schedule panel zooms in and out and resets, and nothing scrolls sideways at any zoom', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await openWalk(page);
  await toKeySchedule(page);
  const zin = page.getByTestId('aes-walk-ks-zoom-in'), zout = page.getByTestId('aes-walk-ks-zoom-out'), zreset = page.getByTestId('aes-walk-ks-zoom-reset');
  if ((await zin.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the Key Schedule panel has no aes-walk-ks-zoom-in yet (Steve fix 3)');
  const width = async () => (await tableCell(page, 0).boundingBox())!.width;
  const flat = async (where: string) => {
    const s = await sideScroll(page);
    expect(s.page, `${where}: the page does not scroll sideways`).toBeLessThanOrEqual(1);
    expect(s.panel, `${where}: the Key Schedule panel does not scroll sideways`).toBeLessThanOrEqual(1);
  };
  await flat('default zoom');
  const base = await width();
  let biggest = base;
  for (let k = 0; k < 6 && await zin.isEnabled(); k++) { await zin.click(); await page.waitForTimeout(250); biggest = Math.max(biggest, await width()); await flat(`zoom in ${k + 1}`); }
  expect(biggest, 'zoom in makes the cells at least 20% larger').toBeGreaterThanOrEqual(base * 1.2);
  await zreset.click(); await page.waitForTimeout(250);
  expect(Math.abs((await width()) - base), 'reset gives the default size back').toBeLessThanOrEqual(1);
  let smallest = base;
  for (let k = 0; k < 6 && await zout.isEnabled(); k++) { await zout.click(); await page.waitForTimeout(250); smallest = Math.min(smallest, await width()); await flat(`zoom out ${k + 1}`); }
  expect(smallest, 'zoom out makes the cells at least 15% smaller').toBeLessThanOrEqual(base * 0.85);
  await zreset.click(); await page.waitForTimeout(250);
  expect(Math.abs((await width()) - base), 'reset after zoom out gives the default size back').toBeLessThanOrEqual(1);
  await flat('after reset');
});

test('[A19.ui.key-panel-landscape-layout] at 1280 px and up the round-key grid sits left of the "How wN is made" panel; below 1280 they stack, and nothing scrolls sideways', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const reply = await openWalk(page);
  await toKeySchedule(page);
  const tables = await hostGet('/api/walk/aes/tables');
  const nk = tables.body.sizes.find((s: any) => s.keyBits === reply.keyBits).keyWords;
  if ((await page.getByTestId('aes-walk-ks-build').count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the Key Schedule panel has no aes-walk-ks-build step panel yet (Steve fix 4)');
  await page.getByTestId('aes-walk-next').click();
  await expect.poll(() => buildTitle(page), { timeout: 15_000 }).toBe(`How w${nk} is made`);
  const boxes = async () => ({ table: (await page.getByTestId('aes-walk-ks-table').boundingBox())!, build: (await page.getByTestId('aes-walk-ks-build').boundingBox())! });
  const flat = async (where: string) => {
    const s = await sideScroll(page);
    expect(s.page, `${where}: the page does not scroll sideways`).toBeLessThanOrEqual(1);
    expect(s.panel, `${where}: the Key Schedule panel does not scroll sideways`).toBeLessThanOrEqual(1);
  };
  for (const width of [1280, 1600]) {
    await page.setViewportSize({ width, height: 800 }); await page.waitForTimeout(300);
    const b = await boxes();
    expect(b.table.x + b.table.width, `${width} px: the grid ends before the step panel starts`).toBeLessThanOrEqual(b.build.x + 1);
    expect(b.build.y, `${width} px: the step panel sits beside the grid, not below it`).toBeLessThan(b.table.y + b.table.height);
    await flat(`${width} px`);
  }
  for (const width of [1279, 1024]) {
    await page.setViewportSize({ width, height: 800 }); await page.waitForTimeout(300);
    const b = await boxes();
    expect(b.build.y, `${width} px: the step panel stacks below the grid`).toBeGreaterThanOrEqual(b.table.y + b.table.height - 1);
    await flat(`${width} px`);
  }
});

/** Per watched testid, every distinct text it showed while visible, sampled once per frame until motion stops (or ms). */
async function textsDuring(page: Page, ids: string[], ms: number): Promise<Record<string, string[]>> {
  return await page.evaluate(({ ids, ms }) => new Promise<Record<string, string[]>>(done => {
    const out: Record<string, string[]> = Object.fromEntries(ids.map(id => [id, [] as string[]]));
    const t0 = performance.now();
    let still = 0;
    const tick = () => {
      const t = performance.now() - t0;
      for (const id of ids) {
        const el = document.querySelector(`[data-testid="${id}"]`) as HTMLElement | null;
        const text = el && el.offsetParent !== null ? (el.textContent ?? '') : '';
        if (text && !out[id].includes(text)) out[id].push(text);
      }
      // A build can pause between its steps with nothing animating (rows about 950 ms apart at normal speed), so only 3 s of stillness ends it.
      still = document.getAnimations().some(a => a.playState === 'running') ? 0 : still + 1;
      if (t > ms || (t > 1500 && still > 180)) done(out); else requestAnimationFrame(tick);
    };
    tick();
  }), { ids, ms });
}

/** The first time each stage row shows the given word's own value, in ms, sampled once per frame. Rows of another word do not count. */
async function stagesWithValues(page: Page, want: Record<string, string>, ms: number): Promise<Record<string, number>> {
  return await page.evaluate(({ want, ms }) => new Promise<Record<string, number>>(done => {
    const seen: Record<string, number> = {};
    const t0 = performance.now();
    const tick = () => {
      const t = performance.now() - t0;
      for (const [id, value] of Object.entries(want)) {
        const el = document.querySelector(`[data-testid="${id}"]`) as HTMLElement | null;
        const shows = !!el && el.offsetParent !== null && Number(getComputedStyle(el).opacity) > 0.5 && (el.textContent ?? '').toLowerCase().includes(value.toLowerCase());
        if (seen[id] === undefined && shows) seen[id] = t;
      }
      if (t > ms || Object.keys(seen).length === Object.keys(want).length) done(seen); else requestAnimationFrame(tick);
    };
    tick();
  }), { want, ms });
}

test('[A19.ui.key-panel-xor-rcon-replay] the build shows each byte XOR in binary, the round-constant strip lights the constant in use, and a tap on a built word replays its build', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const reply = await openWalk(page);
  await toKeySchedule(page);
  const tables = await hostGet('/api/walk/aes/tables');
  const nk = tables.body.sizes.find((s: any) => s.keyBits === reply.keyBits).keyWords;
  const rows: any[] = reply.keyWords.slice().sort((a: any, b: any) => a.i - b.i);
  const row = rows.find(r => r.i === nk);
  if ((await page.getByTestId('aes-walk-ks-build').count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the Key Schedule panel has no aes-walk-ks-build step panel yet (Steve fix 4)');
  // The XOR line, with motion on: for each byte j, one frame shows w(i - Nk) byte j, the value it meets, and the result, each in binary.
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  const [texts] = await Promise.all([textsDuring(page, ['aes-walk-build-xor'], 20_000), page.getByTestId('aes-walk-next').click()]);
  const lines = texts['aes-walk-build-xor'];
  expect(lines.length, `the XOR line shows during the build of w${nk}`).toBeGreaterThan(0);
  const temp: string = row.afterRcon ?? row.substituted ?? row.previous;
  for (let j = 0; j < 4; j++) {
    const parts = [row.keyBack, temp, row.word].map((w: string) => bitsRe(w.slice(2 * j, 2 * j + 2)));
    const hit = lines.some(l => parts.every(p => new RegExp(p).test(l)));
    expect(hit, `byte ${j}: one frame shows ${row.keyBack.slice(2 * j, 2 * j + 2)} XOR ${temp.slice(2 * j, 2 * j + 2)} = ${row.word.slice(2 * j, 2 * j + 2)} in binary`).toBe(true);
  }
  // The round-constant strip: w(Nk) uses constant 1, the first chip. A word with no Rcon lights none, and w(2 Nk) lights the second.
  const lit = async () => {
    const chips = page.locator('[data-testid^="aes-walk-rcon-"][data-lit="true"]');
    const ids: string[] = [];
    for (let k = 0; k < await chips.count(); k++) ids.push((await chips.nth(k).getAttribute('data-testid')) ?? '');
    return ids;
  };
  expect(await lit(), `w${nk} lights round constant 1`).toEqual(['aes-walk-rcon-0']);
  await expect(page.getByTestId('aes-walk-rcon-0')).toContainText(tables.body.rcon.slice(0, 2), { ignoreCase: true });
  await reduced(page);
  await page.getByTestId('aes-walk-next').click();
  expect(await lit(), `w${nk + 1} uses no round constant`).toEqual([]);
  for (let k = nk + 1; k < 2 * nk; k++) await page.getByTestId('aes-walk-next').click();
  expect(await lit(), `w${2 * nk} lights round constant 2`).toEqual(['aes-walk-rcon-1']);
  // Tap a built word: its build plays again, row by row, with its own values.
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  const want: Record<string, string> = {};
  for (const [id, value] of [['previous', row.previous], ['rotated', row.rotated], ['substituted', row.substituted], ['after-rcon', row.afterRcon], ['key-back', row.keyBack], ['word', row.word]])
    want[`aes-walk-build-${id}`] = value;
  const [seen] = await Promise.all([stagesWithValues(page, want, 20_000), tableCell(page, 4 * nk).click()]);
  await expect.poll(() => buildTitle(page), { timeout: 15_000 }).toBe(`How w${nk} is made`);
  const order = Object.keys(want).map(id => seen[id]);
  Object.keys(want).forEach(id => expect(seen[id], `replay of w${nk}: ${id} shows its value`).not.toBeUndefined());
  for (let k = 1; k < order.length; k++) expect(order[k], `replay of w${nk}: ${Object.keys(want)[k]} after ${Object.keys(want)[k - 1]}`).toBeGreaterThanOrEqual(order[k - 1]);
  expect(order[order.length - 1] - order[0], `the replay of w${nk} runs in steps, not in one frame`).toBeGreaterThanOrEqual(300);
});

/** True when the element's box lies fully inside the window. */
const inViewport = (page: Page, testid: string) => page.getByTestId(testid).evaluate(el => {
  const r = el.getBoundingClientRect();
  return r.top >= 0 && r.left >= 0 && r.bottom <= window.innerHeight && r.right <= window.innerWidth;
});

/** True when the element's box lies inside the visible area of the scroll box that holds it. */
const inBox = (page: Page, testid: string, boxId: string) => page.evaluate(({ testid, boxId }) => {
  const el = document.querySelector(`[data-testid="${testid}"]`)!.getBoundingClientRect();
  const box = document.querySelector(`[data-testid="${boxId}"]`)!.getBoundingClientRect();
  return el.top >= box.top - 1 && el.bottom <= box.bottom + 1;
}, { testid, boxId });

/*
 * Steve, 2026-11-08, verbatim: "the left panel grid items need to be in a scrollable container. That way the step buttons on the right do
 * not scroll off-screen when trying to look at the last rounds." Parts (1) and (2) below are his words. Part (3), that Next building words
 * down the table keeps the built word in the box and the window still, is the lead's addition.
 */
test('[A19.ui.key-table-scrolls-in-its-own-box] on AES-256 the round-key table scrolls in its own box: the window stays put, and Next and the step title stay in view', async ({ page }) => {
  for (const [w, h, zoomSteps] of [[1280, 640, 0], [1280, 640, 2], [1984, 1086, 0], [1984, 1086, 2]] as const) {
    await page.setViewportSize({ width: w, height: h });
    await openWalk(page);
    const pick = page.getByTestId('aes-walk-key-size-256');
    if (!(await pick.isVisible().catch(() => false))) throw new NotRun('PRODUCT_MISSING', 'no aes-walk-key-size-256');
    await Promise.all([page.waitForResponse(WALK_BLOCK, { timeout: 30_000 }), pick.click()]);
    await toKeySchedule(page);
    if ((await page.getByTestId('aes-walk-ks-table').count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the Key Schedule panel has no aes-walk-ks-table box yet (Steve: a scrollable container)');
    const where = `${w}x${h}, zoom in x${zoomSteps}`;
    for (let k = 0; k < zoomSteps; k++) await page.getByTestId('aes-walk-ks-zoom-in').click();
    const y0 = await page.evaluate(() => window.scrollY);
    // (1) Steve: look at the last rounds. The table box scrolls to round key 14, and the window does not.
    await page.getByTestId('aes-walk-table-grid-14').evaluate(el => el.scrollIntoView({ block: 'nearest' }));
    await page.waitForTimeout(300);
    expect(await page.evaluate(() => window.scrollY), `${where}: scrolling the table to round key 14 leaves the window where it was`).toBe(y0);
    expect(await inBox(page, 'aes-walk-table-grid-14', 'aes-walk-ks-table'), `${where}: round key 14 is in the table box`).toBe(true);
    // (2) Steve: the step buttons on the right do not scroll off-screen.
    expect(await inViewport(page, 'aes-walk-next'), `${where}: Next stays in view`).toBe(true);
    await page.getByTestId('aes-walk-next').click();
    expect(await inViewport(page, 'aes-walk-ks-build-title'), `${where}: the step title stays in view`).toBe(true);
    // (3) The lead: Next builds words down the table; the word built last is in the table box, and the window did not move.
    await reduced(page);
    for (let k = 0; k < 40; k++) await page.getByTestId('aes-walk-next').click();
    const word = 8 + 41 - 1;
    expect(await inBox(page, `aes-walk-table-cell-${4 * word}`, 'aes-walk-ks-table'), `${where}: w${word}, built last, is in the table box`).toBe(true);
    expect(await page.evaluate(() => window.scrollY), `${where}: building down the table leaves the window where it was`).toBe(y0);
    expect(await inViewport(page, 'aes-walk-next'), `${where}: Next is still in view after 41 words`).toBe(true);
  }
});

/*
 * Steve's block-walk items (2026-11-08), matching the mock's "The block" tab (template.html: #mixcard, renderMix, renderDetail):
 * 1. the MixColumns matrix panel: the fixed matrix times the column gives the state after, the pair lit, the "2 × 21 = 42" line,
 *    Play this column, and Fill all;
 * 2. AddRoundKey shows a "ROUND KEY n" grid with its number, and the XOR is animated;
 * 3. the bit lines for the selected byte: state XOR key = result, in bits, in color.
 * Every value comes from the Host's reply: step.terms[r + 4c].parts[k] (factor, input, result) and step.roundKey.
 */

/** The fixed MixColumns matrix, FIPS 197 section 5.1.3. Written out here; no value comes from the app. */
const MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];

/** Next until the first step of the given kind in the encrypt run. Returns its index in reply.forward.steps. */
async function toStep(page: Page, reply: any, kind: string, round: number): Promise<number> {
  const idx = reply.forward.steps.findIndex((s: any) => s.kind === kind && s.round === round);
  await toFirstStep(page);
  for (let n = 0; n < idx; n++) await page.getByTestId('aes-walk-next').click();
  expect(await kindNow(page), `at ${kind} round ${round}`).toBe(kind);
  return idx;
}

const dataHex = async (page: Page, testid: string) => ((await page.getByTestId(testid).getAttribute('data-hex')) ?? '').toLowerCase();

/** Per frame: the lit matrix cell, the lit state-before cell, and the line, as one string. Ends when the column's 4 bytes of the state after
 *  are filled, or at ms. Play can wait between products with nothing animating, so stillness cannot mark the end. */
async function pairFrames(page: Page, col: number, ms: number): Promise<string[]> {
  return await page.evaluate(({ col, ms }) => new Promise<string[]>(done => {
    const out: string[] = [];
    const t0 = performance.now();
    const filled = () => [0, 1, 2, 3].every(r => (document.querySelector(`[data-testid="aes-walk-mix-after-${r}-${col}"]`)?.getAttribute('data-hex') ?? '') !== '');
    const tick = () => {
      const t = performance.now() - t0;
      const m = document.querySelector('[data-testid^="aes-walk-mix-matrix-"][data-pair="true"]')?.getAttribute('data-testid') ?? '';
      const b = document.querySelector('[data-testid^="aes-walk-mix-before-"][data-pair="true"]')?.getAttribute('data-testid') ?? '';
      const line = (document.querySelector('[data-testid="aes-walk-mix-line"]')?.textContent ?? '').replace(/\s+/g, ' ').trim();
      const f = `${m}|${b}|${line}`;
      if (m && out[out.length - 1] !== f) out.push(f);
      if (t > ms || filled()) done(out); else requestAnimationFrame(tick);
    };
    tick();
  }), { col, ms });
}

test('[A19.ui.mix-matrix-pairs-and-line] on MixColumns the panel shows the fixed matrix, the state before, and Play this column lights each pair with its "2 × 21 = 42" line and fills that column', async ({ page }) => {
  const reply = await openWalk(page);
  const idx = await toStep(page, reply, 'MixColumns', 1);
  if ((await page.getByTestId('aes-walk-mix-panel').count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'MixColumns has no aes-walk-mix-panel yet (Steve: the matrix panel)');
  const step = reply.forward.steps[idx];
  const before = bytesOf(reply.forward.steps[idx - 1].state);
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) {
    const f = ((await page.getByTestId(`aes-walk-mix-matrix-${r}-${c}`).textContent()) ?? '').trim();
    expect(parseInt(f, 16), `matrix row ${r}, column ${c}`).toBe(MIX[r][c]);
    expect(await dataHex(page, `aes-walk-mix-before-${r}-${c}`), `state before, row ${r}, column ${c}`).toBe(before[r + 4 * c]);
  }
  // A picked byte picks its column. Column 2 here, so a panel stuck on column 0 fails.
  const col = 2;
  await cell(page, 1, col).click();
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  const [frames] = await Promise.all([pairFrames(page, col, 120_000), page.getByTestId('aes-walk-mix-play').click()]);
  expect(frames.length, 'Play this column lights pairs').toBeGreaterThan(0);
  for (let r = 0; r < 4; r++) for (let k = 0; k < 4; k++) {
    const p = step.terms[r + 4 * col].parts[k];
    // The line's text can run straight into the next words ("= 5dRow 0 ..."), so the result ends at the first character that is not hex.
    const line = new RegExp(`(?<![0-9a-f])${p.factor}\\s*[×x]\\s*${p.input}\\s*=\\s*${p.result}(?![0-9a-f])`, 'i');
    const hit = frames.some(fr => { const [m, b, l] = fr.split('|'); return m === `aes-walk-mix-matrix-${r}-${k}` && b === `aes-walk-mix-before-${k}-${col}` && line.test(l); });
    expect(hit, `row ${r}, pair ${k}: the matrix cell and byte ${k} of column ${col} are lit together, with the line "${p.factor} × ${p.input} = ${p.result}"`).toBe(true);
  }
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++)
    expect(await dataHex(page, `aes-walk-mix-after-${r}-${c}`), `after Play, row ${r}, column ${c}`).toBe(c === col ? step.terms[r + 4 * c].result.toLowerCase() : '');
});

test('[A19.ui.mix-fill-all] on MixColumns, Fill all fills every byte of the state after with the engine state', async ({ page }) => {
  const reply = await openWalk(page);
  const idx = await toStep(page, reply, 'MixColumns', 1);
  if ((await page.getByTestId('aes-walk-mix-fill').count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'MixColumns has no aes-walk-mix-fill yet (Steve: Fill all)');
  const after = bytesOf(reply.forward.steps[idx].state);
  await page.getByTestId('aes-walk-mix-fill').click();
  await expect.poll(() => running(page), { timeout: 30_000 }).toBe(0);
  for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++)
    expect(await dataHex(page, `aes-walk-mix-after-${r}-${c}`), `after Fill all, row ${r}, column ${c}`).toBe(after[r + 4 * c]);
});

test('[A19.ui.add-round-key-grid] AddRoundKey shows a "ROUND KEY n" grid with its number and the engine round key, and the XOR moves with motion on', async ({ page }) => {
  const reply = await openWalk(page);
  await toFirstStep(page);
  if ((await page.getByTestId('aes-walk-round-key-grid').count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'AddRoundKey has no aes-walk-round-key-grid yet (Steve: the ROUND KEY n grid)');
  const check = async (idx: number) => {
    const s = reply.forward.steps[idx];
    await expect(page.getByTestId('aes-walk-round-key-label'), `round ${s.round}: the grid names its number`).toHaveText(new RegExp(`round key\\s*${s.round}\\b`, 'i'));
    const key = bytesOf(s.roundKey);
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++)
      expect(await dataHex(page, `aes-walk-round-key-cell-${r}-${c}`), `round key ${s.round}, row ${r}, column ${c}`).toBe(key[r + 4 * c]);
  };
  await check(0);
  // Round 1's AddRoundKey, reached with motion on: the XOR moves on screen, and the end frame is the engine state.
  const idx1 = reply.forward.steps.findIndex((s: any) => s.kind === 'AddRoundKey' && s.round === 1);
  for (let n = 0; n < idx1 - 1; n++) await page.getByTestId('aes-walk-next').click();
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  const [moved] = await Promise.all([
    page.evaluate(() => new Promise<boolean>(done => {
      const t0 = performance.now();
      const tick = () => {
        const block = document.querySelector('[data-testid="aes-walk-block"]');
        const hit = document.getAnimations().some(a => a.playState === 'running' && block?.contains((a.effect as KeyframeEffect | null)?.target as Node));
        if (hit) done(true); else if (performance.now() - t0 > 3000) done(false); else requestAnimationFrame(tick);
      };
      tick();
    })),
    page.getByTestId('aes-walk-next').click(),
  ]);
  expect(await kindNow(page), 'at AddRoundKey round 1').toBe('AddRoundKey');
  expect(moved, 'the XOR moves on screen with motion on').toBe(true);
  await expect.poll(() => running(page), { timeout: 30_000 }).toBe(0);
  await check(idx1);
  expect(await grid(page), 'the end frame is the engine state').toBe(reply.forward.steps[idx1].state.toLowerCase());
});

test('[A19.ui.bit-lines-for-picked-byte] on AddRoundKey a picked byte shows state XOR key = result in bits, with the key and result lines in their own colors', async ({ page }) => {
  const reply = await openWalk(page);
  await toFirstStep(page);
  const s = reply.forward.steps[0];
  const prev = bytesOf(reply.inputHex), key = bytesOf(s.roundKey), out = bytesOf(s.state);
  await cell(page, 0, 0).click();
  if ((await page.getByTestId('aes-walk-bits-state').count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'AddRoundKey has no aes-walk-bits-state yet (Steve: the bit lines)');
  for (const [r, c] of [[0, 0], [2, 3]]) {
    await cell(page, r, c).click();
    const i = r + 4 * c;
    for (const [id, h] of [['state', prev[i]], ['key', key[i]], ['result', out[i]]] as const)
      await expect(page.getByTestId(`aes-walk-bits-${id}`), `byte ${i}: the ${id} line in bits`).toHaveText(new RegExp(bitsRe(h)));
  }
  const color = (id: string) => page.getByTestId(`aes-walk-bits-${id}`).evaluate(e => getComputedStyle(e).color);
  const [cs, ck, cr] = [await color('state'), await color('key'), await color('result')];
  expect(ck, 'the key line has its own color').not.toBe(cs);
  expect(cr, 'the result line has its own color').not.toBe(cs);
  expect(cr, 'the key and result lines differ').not.toBe(ck);
});

/*
 * The decrypt walk's InvMixColumns lines (Jared on #329, the lead's follow-up). #330's real bug sat on this path, and only Nancy's own spec
 * covered it. This clause checks the screen against the suite's own field multiply, so it shares no code with the app or the engine.
 */

/** Multiply by 2 in GF(2^8) with the AES polynomial 11b (FIPS 197 section 4.2.1). */
const xtime = (b: number) => ((b << 1) & 0x100 ? (b << 1) ^ 0x11b : b << 1);
/** f times b in GF(2^8): XOR of the doublings that f's set bits pick (FIPS 197 section 4.2). */
function gmul(f: number, b: number): number {
  let r = 0, p = b;
  for (let i = 0; i < 4; i++) { if (f & (1 << i)) r ^= p; p = xtime(p); }
  return r;
}
const h2 = (n: number) => n.toString(16).padStart(2, '0');

/** Row 0 of the InvMixColumns matrix, FIPS 197 section 5.3.3: 0e 0b 0d 09. Pair k of row 0 meets byte k of the column. */
const INV_ROW0 = [14, 11, 13, 9];

test('[A19.ui.inv-mix-line-matches-field-multiply] on the decrypt walk\'s InvMixColumns, each of the factors 14, 11, 13 and 9 shows its product, its doublings and its "N is 8 + ..." breakdown as the suite\'s own field multiply gives them', async ({ page }) => {
  const reply = await openWalk(page);
  await toFirstStep(page);
  for (let n = 0; n < 200 && (await kindNow(page)) !== 'InvMixColumns'; n++) await page.getByTestId('aes-walk-next').click();
  expect(await kindNow(page), 'at the decrypt walk\'s first InvMixColumns').toBe('InvMixColumns');
  if ((await page.getByTestId('aes-walk-mix-next').count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'InvMixColumns has no aes-walk-mix-next yet');
  const idx = reply.inverse.steps.findIndex((s: any) => s.kind === 'InvMixColumns');
  const before = bytesOf(reply.inverse.steps[idx - 1].state);
  for (let k = 0; k < 4; k++) {
    const f = INV_ROW0[k], b = parseInt(before[k], 16);
    const d1 = xtime(b), d2 = xtime(d1), d3 = xtime(d2), want = gmul(f, b);
    const parts = [8, 4, 2, 1].filter(p => (f & p) !== 0).join(' + ');
    const line = ((await page.getByTestId('aes-walk-mix-line').textContent()) ?? '').replace(/\s+/g, ' ');
    const where = `column 0, pair ${k} (factor ${f}, byte ${before[k]})`;
    expect(new RegExp(`(?<![0-9a-f])${f}\\s*[×x]\\s*${before[k]}\\s*=\\s*${h2(want)}(?![0-9a-f])`, 'i').test(line), `${where}: the line reads ${f} × ${before[k]} = ${h2(want)}, and reads "${line}"`).toBe(true);
    expect(line, `${where}: the breakdown names ${f}'s powers of 2`).toContain(`${f} is ${parts}`);
    for (const [name, v] of [['x2', d1], ['x4', d2], ['x8', d3]] as const)
      expect(new RegExp(`${name}\\s*=\\s*${h2(v)}(?![0-9a-f])`, 'i').test(line), `${where}: the doubling ${name} = ${h2(v)} shows, and the line reads "${line}"`).toBe(true);
    if (k < 3) await page.getByTestId('aes-walk-mix-next').click();
  }
});
