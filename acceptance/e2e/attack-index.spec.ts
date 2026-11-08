import { expect, test, type Page } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { NotRun, hostGet, openApp, requireLive } from './support';

/**
 * P3, the attack index and the two-run layout (docs/sections-plan.md section 2 item 3, and Q4 answer A). "Attack runs" opens an index of all
 * registered runs grouped by kind. Each row names the attack, its lesson, and the check that catches it, and no run goes without a group.
 * A click opens the normal run beside the attacked run: the changed message diffed in Message bytes with the changed bytes lit, and the
 * catching check under both, pass on the left and fail on the right. A scenario attack's pairs end where the runs part, and the screen marks
 * that point. Back returns to the index with the row kept.
 * The registry is the live Host's (GET /api/lessons and /api/lessons/0, which list AttackCatalog), never a text count. The group of a run is its
 * kind in app/src/attacks.json (the content half of P3).
 * Test ids (Nancy's P3 plan, 2026-11-08): attack-index-open in the Lessons rail; attack-index; attack-group-{labelId}; attack-row-{attackId}
 * with data-kind and data-lesson, holding attack-row-name, attack-row-check and attack-row-guard; two-run with two-run-normal and
 * two-run-attacked; two-run-check-normal and two-run-check-attacked with data-result pass|fail|none; two-run-diff with data-changed="true"
 * on each changed byte; two-run-split; two-run-back, and data-kept="true" on the kept row.
 * Where Lessons has no attack index yet, these clauses read NOT RUN.
 */

test.describe.configure({ timeout: 180_000 });
test.use({ actionTimeout: 15_000 });

type Row = { attackId: string; kind: string; lesson: number; expectCode: string | null; expectCheck: string | null; whyNot: string | null };

/** Every registered attack run, from the live Host. Lesson 0 has its own route. */
async function registry(): Promise<Row[]> {
  const lessons = await hostGet('/api/lessons');
  expect(lessons.status, 'GET /api/lessons').toBe(200);
  const zero = await hostGet('/api/lessons/0');
  expect(zero.status, 'GET /api/lessons/0').toBe(200);
  const listed: any[] = Array.isArray(lessons.body) ? lessons.body : lessons.body?.lessons ?? [];
  const rows: Row[] = [];
  for (const l of [zero.body, ...listed]) for (const a of l.attacks ?? []) rows.push({ attackId: a.attackId, kind: a.kind, lesson: Number(l.lesson), expectCode: a.expectCode ?? null, expectCheck: a.expectCheck ?? null, whyNot: a.whyNot ?? null });
  return rows;
}

/** attacks.json: the labels and each run's group, read from the product tree the run serves. */
function content(): { labels: string[]; groupOf: Map<string, string> } {
  const root = process.env.ACC_ROOT ?? '';
  const file = path.join(root, 'app', 'src', 'attacks.json');
  if (!fs.existsSync(file)) throw new NotRun('PRODUCT_MISSING', `${file} does not exist yet (P3 content half)`);
  const d = JSON.parse(fs.readFileSync(file, 'utf8'));
  return { labels: (d.labels ?? []).map((l: any) => l.id), groupOf: new Map((d.runs ?? []).map((r: any) => [r.attackId, r.kind])) };
}

async function openIndex(page: Page): Promise<void> {
  requireLive();
  await openApp(page);
  const section = page.getByTestId('section-lessons');
  if ((await section.count()) > 0) await section.click();
  const open = page.getByTestId('attack-index-open');
  if ((await open.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'the Lessons rail has no attack-index-open yet (slice P3)');
  await open.click();
  await expect(page.getByTestId('attack-index'), 'attack-index-open opens the index').toBeVisible({ timeout: 15_000 });
}

/** Opens one row's two-run layout. */
async function openRun(page: Page, id: string): Promise<void> {
  await page.getByTestId(`attack-row-${id}`).click();
  await expect(page.getByTestId('two-run'), `${id} opens the two-run layout`).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId('two-run-normal'), `${id}: the normal run`).toBeVisible();
  await expect(page.getByTestId('two-run-attacked'), `${id}: the attacked run`).toBeVisible();
}

test('[A19.ui.attack-index-lists-every-run] the index shows every run the Host registers, each in its group, naming its lesson and its check', async ({ page }) => {
  const rows = await registry();
  const { labels, groupOf } = content();
  await openIndex(page);
  const missing: string[] = [], wrong: string[] = [];
  for (const r of rows) {
    const group = groupOf.get(r.attackId);
    if (!group || !labels.includes(group)) { wrong.push(`${r.attackId}: no group in attacks.json`); continue; }
    const row = page.getByTestId(`attack-group-${group}`).getByTestId(`attack-row-${r.attackId}`);
    if ((await row.count()) !== 1) { missing.push(`${r.attackId} (group ${group})`); continue; }
    if ((await row.getAttribute('data-lesson')) !== String(r.lesson)) wrong.push(`${r.attackId}: data-lesson is ${await row.getAttribute('data-lesson')}, and the Host says ${r.lesson}`);
    if ((await row.getAttribute('data-kind')) !== group) wrong.push(`${r.attackId}: data-kind is ${await row.getAttribute('data-kind')}, and attacks.json says ${group}`);
    if (!((await row.getByTestId('attack-row-name').innerText()) ?? '').trim()) wrong.push(`${r.attackId}: the row names no attack`);
    const check = ((await row.getByTestId('attack-row-check').innerText()) ?? '').trim();
    if (r.expectCheck && !check.includes(r.expectCheck)) wrong.push(`${r.attackId}: the row's check reads "${check}", and the Host's catching check is ${r.expectCheck}`);
  }
  expect(missing, `${missing.length} of ${rows.length} registered runs have no row in their group`).toEqual([]);
  expect(wrong, 'rows that name the wrong lesson, kind or check').toEqual([]);
  expect(await page.locator('[data-testid^="attack-row-"][data-kind]').count(), 'one row per registered run, and no extra rows').toBe(rows.length);
  for (const g of labels) {
    const el = page.getByTestId(`attack-group-${g}`);
    if ((await el.count()) > 0) expect(await el.locator('[data-testid^="attack-row-"][data-kind]').count(), `the group ${g} renders, so it holds a row`).toBeGreaterThan(0);
  }
});
