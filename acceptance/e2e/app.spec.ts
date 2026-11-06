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
  if (built === 0) throw new NotRun('LESSON_NOT_BUILT', 'the Host lists no built lesson yet');
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
    // Time budget, from measured walks (e759e8a, live Host): lessons 1 to 4 take about 15 s; lesson 5 takes 43 s, of which 30 s is the lab's own
    // read deadline in step L5-S12 (a wall-clock timer, so machine load does not stretch it). Under load the other steps ran about 5 times slower.
    // A hang is found per step: Next must enable within 45 s of its step (30 s deadline plus slack), and the failure names the step.
    // The whole walk gets 60 s plus 20 s for each step, so slow machines do not fail a walk that moves, and a stalled step still ends the walk at 45 s.
    test.setTimeout(60_000 + 20_000 * ids.length);
    expect(ids.length, `tour steps in app/src/tours/lesson-${String(n).padStart(2, '0')}.json`).toBeGreaterThan(0);
    await openApp(page);
    await page.getByTestId(`lesson-item-${n}`).click();
    const start = page.getByRole('button', { name: /start tour/i });
    if (await start.isVisible().catch(() => false)) await start.click();
    await expect(page.getByTestId('tour-panel')).toBeVisible({ timeout: 30_000 });

    const dir = path.join(OUT, `lesson-${n}`);
    fs.mkdirSync(dir, { recursive: true });
    const visited: string[] = [];
    const stepMs: string[] = [];
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
      // The reason text is read AFTER the wait, with a short timeout. The element exists only while Next is disabled, so a read with the
      // default timeout blocks until the whole test times out when Next is already enabled. That hid the step id behind "Test timeout".
      const stepStart = Date.now();
      try { await expect(next).toBeEnabled({ timeout: 45_000 }); }
      catch {
        const why = await reason.textContent({ timeout: 1000 }).catch(() => '');
        throw new Error(`Next never enabled at step ${id}; reason shown: ${why ?? ''}`);
      }
      stepMs.push(`${id}=${Date.now() - stepStart}ms`);
      if (id === ids[ids.length - 1]) break;
      await next.click();
    }
    expect(visited, `the steps the app showed against the tour file`).toEqual(ids);
    test.info().annotations.push({ type: 'walk-time', description: `lesson ${n}: ${ids.length} steps; wait for Next per step: ${stepMs.join(' ')}` });
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

test('[A16.ui.os-transport-label-and-hidden-secrets] the chip reads OS TRANSPORT and the secrets panel hides values', async ({ page }) => {
  requireLive();
  await openApp(page);
  const sw = page.getByTestId('transport-switch');
  if ((await sw.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'no element with data-testid transport-switch; ux-design.md names no testid for the OS transport switch (CONTRACT.md asks for one)');
  await sw.click();
  await expect(page.getByTestId('training-only-label')).toContainText(/OS TRANSPORT/);
  const rows = page.locator('[data-testid^="secret-row-"]');
  expect(await rows.count(), 'secret rows shown on the OS transport').toBe(0);
});

/**
 * A17: the Show keys switch (modes-design.md section 6, test id show-keys-switch). The Host holds the truth: GET /api/security/show-keys.
 * The renderer must agree with it, show key bytes while ON, and show a fingerprint and the banner while OFF. The key compare of two different keys
 * is covered through the API by A17.show-keys.fingerprint-compare, since the panel's markup for a match has no test id in the design.
 */
test('[A17.ui.show-keys-switch] on by default; off replaces key bytes with fingerprints and shows the banner; on brings the bytes back', async ({ page }) => {
  requireLive();
  const host0 = await hostGet('/api/security/show-keys');
  if (host0.status === 404) throw new NotRun('PRODUCT_MISSING', 'GET /api/security/show-keys does not exist yet (slice V3)');
  expect(host0.status, 'GET /api/security/show-keys').toBe(200);
  expect(host0.body?.on, 'the Host starts with Show keys ON').toBe(true);
  await openApp(page);
  const sw = page.getByTestId('show-keys-switch');
  if ((await sw.count()) === 0) throw new NotRun('UI_CONTROL_MISSING', 'no element with data-testid show-keys-switch (modes-design.md section 6)');
  const isOn = async () => (await sw.getAttribute('aria-checked')) === 'true' || (await sw.isChecked().catch(() => false));
  expect(await isOn(), 'the switch reads ON by default').toBe(true);

  const lessons = await hostGet('/api/lessons');
  const rows: any[] = Array.isArray(lessons.body) ? lessons.body : lessons.body?.lessons ?? [];
  const built = rows.find(r => r.built);
  if (!built) throw new NotRun('LESSON_NOT_BUILT', 'no lesson is built, so no secrets panel can fill');
  await page.getByTestId(`lesson-item-${built.lesson}`).click();
  const start = page.getByRole('button', { name: /start tour/i });
  if (await start.isVisible().catch(() => false)) await start.click();
  const secretRows = page.locator('[data-testid^="secret-row-"]');
  // Lesson 1 starts on concept steps, and its key reaches the secrets panel when the tour reaches the step that binds keys.installed.
  // On the V3 Host key.in-use carries secrets: [] on purpose. So the clause walks the tour with Next, one step at a time, until a row shows.
  // The clause names no step number, so a tour that adds a step does not move it. The cap only stops a tour that never shows a row.
  const nextBtn = page.getByTestId('tour-next');
  for (let hop = 0; hop < 30 && (await secretRows.count()) === 0; hop++) {
    await expect(nextBtn, 'Next is available while no secret row shows').toBeEnabled({ timeout: 45_000 });
    await nextBtn.click();
    await page.waitForTimeout(2_000);
  }
  await expect.poll(async () => await secretRows.count(), { timeout: 45_000, message: 'secret rows while Show keys is ON, after walking the tour' }).toBeGreaterThan(0);
  const textOf = async () => (await secretRows.allInnerTexts()).join('\n');
  expect(await textOf(), 'ON: a row shows key bytes').toMatch(/[0-9a-f]{16,}/i);

  await sw.click();
  await expect.poll(async () => (await hostGet('/api/security/show-keys')).body?.on, { timeout: 15_000, message: 'the Host follows the switch to OFF' }).toBe(false);
  expect(await isOn(), 'the switch reads OFF after the click').toBe(false);
  await expect.poll(async () => /[0-9a-f]{32,}/i.test(await textOf()), { timeout: 15_000, message: 'key bytes leave the panel at once when the switch goes OFF' }).toBe(false);
  expect(await textOf(), 'OFF: a row shows a fingerprint').toMatch(/fp:[0-9a-f]{8,}/i);
  await expect(page.getByText(/Show keys is off/i).first(), 'the OFF banner').toBeVisible();

  await sw.click();
  await expect.poll(async () => (await hostGet('/api/security/show-keys')).body?.on, { timeout: 15_000, message: 'the Host follows the switch back to ON' }).toBe(true);
  await expect.poll(async () => /[0-9a-f]{16,}/i.test(await textOf()), { timeout: 15_000, message: 'key bytes return for an open session when the switch goes ON' }).toBe(true);
});
