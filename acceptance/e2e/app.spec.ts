import { expect, test } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { NotRun, OUT, hostGet, openApp, requireLive, tourSteps } from './support';

/**
 * A13: the Electron app's renderer starts against a live Host and walks every step of every built lesson. Never a recorded fixture.
 * The title of each test starts with its clause id in square brackets. run.ps1 reads the JSON report by that id.
 * Test ids come from ux-design.md section 6 and never change after S8.
 */

test('[A13.app-starts-against-live-host] app root, host chip connected, a rail of 11 lessons', async ({ page }) => {
  requireLive();
  await openApp(page);
  await expect(page.getByTestId('app-root')).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId('host-chip')).toContainText(/connected/i, { timeout: 30_000 });
  await expect(page.getByTestId('lesson-rail')).toBeVisible();
  for (let n = 1; n <= 11; n++) await expect(page.getByTestId(`lesson-item-${n}`)).toBeVisible();
  fs.mkdirSync(OUT, { recursive: true });
  await page.screenshot({ path: path.join(OUT, 'app-start.png') });
});

test('[A13.home-page-shows-built-and-unbuilt-lessons] the rail agrees with GET /api/lessons', async ({ page }) => {
  requireLive();
  const lessons = await hostGet('/api/lessons');
  expect(lessons.status, 'GET /api/lessons').toBe(200);
  const rows: any[] = Array.isArray(lessons.body) ? lessons.body : lessons.body?.lessons ?? [];
  expect(rows.length, 'lessons the Host lists').toBe(11);
  await openApp(page);
  for (const row of rows) {
    const n = row.lesson;
    await expect(page.getByTestId(`lesson-status-${n}`)).toBeVisible();
  }
  const built = rows.filter(r => r.built).length;
  expect(built, 'built lessons listed by the Host').toBeGreaterThan(0);
});

for (let n = 1; n <= 11; n++) {
  test(`[A13.walk.lesson-${n}] every step of lesson ${n}, live Host, screenshots saved`, async ({ page }) => {
    requireLive();
    const lessons = await hostGet('/api/lessons');
    const rows: any[] = Array.isArray(lessons.body) ? lessons.body : lessons.body?.lessons ?? [];
    const row = rows.find(r => r.lesson === n);
    if (!row || !row.built) {
      test.info().annotations.push({ type: 'notrun', description: `LESSON_NOT_BUILT: lesson ${n} is not built yet` });
      test.skip(true, `LESSON_NOT_BUILT: lesson ${n}`);
      return;
    }
    const ids: string[] = tourSteps(n).map((s: any) => s.id);
    expect(ids.length, `tour steps in app/src/tours/lesson-${String(n).padStart(2, '0')}.json`).toBeGreaterThan(0);
    await openApp(page);
    await page.getByTestId(`lesson-item-${n}`).click();
    const start = page.getByRole('button', { name: /start tour/i });
    if (await start.isVisible().catch(() => false)) await start.click();
    await expect(page.getByTestId('tour-panel')).toBeVisible({ timeout: 30_000 });

    const dir = path.join(OUT, `lesson-${n}`);
    fs.mkdirSync(dir, { recursive: true });
    const visited: string[] = [];
    for (let i = 0; i < ids.length + 5; i++) {
      await expect(page.getByTestId('tour-step-id')).not.toHaveText('', { timeout: 30_000 });
      const id = ((await page.getByTestId('tour-step-id').textContent()) ?? '').trim();
      visited.push(id);
      await expect(page.getByTestId('error-banner'), `an error banner at step ${id}`).toHaveCount(0);
      await page.screenshot({ path: path.join(dir, `${id}.png`) });
      const next = page.getByTestId('tour-next');
      if (await next.isDisabled()) {
        const tryIt = page.getByTestId('tour-try-it-action');
        if (await tryIt.isVisible().catch(() => false)) await tryIt.click();
      }
      // A disabled Next always names its reason (ux-design.md section 3.2). If it never enables, the reason goes into the failure.
      const reason = page.getByTestId('next-reason');
      await expect(next, `Next never enabled at step ${id}; reason shown: ${(await reason.textContent().catch(() => '')) ?? ''}`).toBeEnabled({ timeout: 45_000 });
      if (id === ids[ids.length - 1]) break;
      await next.click();
    }
    expect(visited, `the steps the app showed against the tour file`).toEqual(ids);
  });
}

test('[A16.ui.training-only-label-on-glass] the chip reads TRAINING ONLY on a glass-box session', async ({ page }) => {
  requireLive();
  await openApp(page);
  const lessons = await hostGet('/api/lessons');
  const rows: any[] = Array.isArray(lessons.body) ? lessons.body : lessons.body?.lessons ?? [];
  const firstBuilt = rows.find(r => r.built);
  if (!firstBuilt) throw new NotRun('LESSON_NOT_BUILT', 'no lesson is built, so no glass-box session can start');
  await page.getByTestId(`lesson-item-${firstBuilt.lesson}`).click();
  const start = page.getByRole('button', { name: /start tour/i });
  if (await start.isVisible().catch(() => false)) await start.click();
  const chip = page.getByTestId('training-only-label');
  await expect(chip).toBeVisible({ timeout: 30_000 });
  await expect(chip).toContainText(/TRAINING ONLY/);
});

test('[A16.ui.os-transport-label-in-real-mode] the chip reads OS TRANSPORT and the secrets panel hides values', async ({ page }) => {
  requireLive();
  await openApp(page);
  const sw = page.getByTestId('transport-switch');
  if ((await sw.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'no element with data-testid transport-switch; ux-design.md names no testid for the real-mode switch (CONTRACT.md asks for one)');
  await sw.click();
  await expect(page.getByTestId('training-only-label')).toContainText(/OS TRANSPORT/);
  const rows = page.locator('[data-testid^="secret-row-"]');
  expect(await rows.count(), 'secret rows shown in real mode').toBe(0);
});
