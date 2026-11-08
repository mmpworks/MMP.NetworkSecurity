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
 * The registry is the live Host's (GET /api/lessons, lessons 0 to 11, which lists AttackCatalog), never a text count. The group of a run is its
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

/** Every registered attack run, from the live Host. GET /api/lessons lists lessons 0 to 11 (#303), so one list holds them all. */
async function registry(): Promise<Row[]> {
  const lessons = await hostGet('/api/lessons');
  expect(lessons.status, 'GET /api/lessons').toBe(200);
  const listed: any[] = Array.isArray(lessons.body) ? lessons.body : lessons.body?.lessons ?? [];
  expect(listed.some(l => Number(l.lesson) === 0), 'GET /api/lessons lists lesson 0').toBe(true);
  const rows: Row[] = [];
  for (const l of listed) for (const a of l.attacks ?? []) rows.push({ attackId: a.attackId, kind: a.kind, lesson: Number(l.lesson), expectCode: a.expectCode ?? null, expectCheck: a.expectCheck ?? null, whyNot: a.whyNot ?? null });
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
  // The split marker and the lit bytes appear once both runs have finished; until then two-run-running shows (Nancy's P3b note).
  await expect(page.getByTestId('two-run-running'), `${id}: both runs finish`).toHaveCount(0, { timeout: 90_000 });
}

test('[A19.ui.two-run-flip-shows-diff-and-checks] a caught flip-byte run opens side by side, its changed bytes lit, the check passing left and failing right', async ({ page }) => {
  const rows = await registry();
  const pick = rows.find(r => r.kind === 'flip-byte' && r.expectCheck);
  if (!pick) throw new NotRun('LESSON_NOT_BUILT', 'the Host registers no caught flip-byte run');
  await openIndex(page);
  await openRun(page, pick.attackId);
  await expect(page.getByTestId('two-run-check-normal'), `${pick.attackId}: the check under the normal run`).toHaveAttribute('data-result', 'pass', { timeout: 60_000 });
  await expect(page.getByTestId('two-run-check-attacked'), `${pick.attackId}: the check under the attacked run`).toHaveAttribute('data-result', 'fail', { timeout: 60_000 });
  const diff = page.getByTestId('two-run-diff');
  await expect(diff, `${pick.attackId}: Message bytes diffs the changed message`).toBeVisible();
  expect(await diff.locator('[data-changed="true"]').count(), `${pick.attackId}: at least one changed byte is lit`).toBeGreaterThan(0);
});

test('[A19.ui.two-run-scenario-marks-split] a scenario run marks where the two runs part', async ({ page }) => {
  const rows = await registry();
  const pick = rows.find(r => r.kind && r.kind !== 'flip-byte');
  if (!pick) throw new NotRun('LESSON_NOT_BUILT', 'the Host registers no scenario run');
  await openIndex(page);
  await openRun(page, pick.attackId);
  await expect(page.getByTestId('two-run-split'), `${pick.attackId} (${pick.kind}): the screen marks the point where the runs part`).toBeVisible({ timeout: 60_000 });
});

test('[A19.ui.two-run-nothing-catches-shows-none] a run that nothing catches shows no check result on the attacked side', async ({ page }) => {
  const rows = await registry();
  const pick = rows.find(r => !r.expectCheck);
  if (!pick) throw new NotRun('LESSON_NOT_BUILT', 'every registered run names a catching check');
  await openIndex(page);
  await openRun(page, pick.attackId);
  await expect(page.getByTestId('two-run-check-attacked'), `${pick.attackId}: nothing catches it, so the attacked side shows none`).toHaveAttribute('data-result', 'none', { timeout: 60_000 });
});

test('[A19.ui.two-run-back-keeps-row] Back returns to the index with the opened row kept', async ({ page }) => {
  const rows = await registry();
  const pick = rows[0];
  if (!pick) throw new NotRun('LESSON_NOT_BUILT', 'the Host registers no attack run');
  await openIndex(page);
  await openRun(page, pick.attackId);
  await page.getByTestId('two-run-back').click();
  await expect(page.getByTestId('attack-index'), 'Back returns to the index').toBeVisible({ timeout: 15_000 });
  const row = page.getByTestId(`attack-row-${pick.attackId}`);
  await expect(row, `${pick.attackId} is kept`).toHaveAttribute('data-kept', 'true');
  await expect(row, `${pick.attackId} has the focus`).toBeFocused();
});
