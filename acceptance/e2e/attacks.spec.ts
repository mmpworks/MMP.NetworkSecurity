import { test, expect } from '@playwright/test';
import { openApp, hostGet, requireLive, NotRun } from './support';

/**
 * prd.md line 93: "Every lesson has attack buttons." The rows come from the live Host's GET /api/lessons and GET /api/lessons/0, which list AttackCatalog,
 * so the count is never taken from a text search. Each row must have its button, data-testid attack-{attackId}, in its lesson's drawer.
 * A17.attacks.every-row-forks-to-its-code checks that each row's fork ends with its code and names its check.
 */
test('[A17.ui.every-attack-row-has-a-button] each attack row the Host lists has its button in its lesson', async ({ page }) => {
  test.setTimeout(15 * 60_000);
  requireLive();
  // Named defect, for the proof that this clause bites: ACC_E2E_DEFECT=attack-button-missing removes one row from the browser's copy of
  // GET /api/lessons, so the app draws no button for it. The clause reads the Host itself, still expects that row, and must FAIL naming it.
  if (process.env.ACC_E2E_DEFECT === 'attack-button-missing') {
    await page.route('**/api/lessons', async route => {
      const response = await route.fetch();
      const body = await response.json();
      const list: any[] = Array.isArray(body) ? body : body?.lessons ?? [];
      const target = list.find(l => Array.isArray(l.attacks) && l.attacks.length > 0);
      if (target) target.attacks = target.attacks.slice(1);
      await route.fulfill({ response, json: body });
    });
  }
  await openApp(page);
  const lessons = await hostGet('/api/lessons');
  expect(lessons.status, 'GET /api/lessons').toBe(200);
  const listed: any[] = Array.isArray(lessons.body) ? lessons.body : lessons.body?.lessons ?? [];
  // The list holds lessons 1 to 11. Lesson 0 has its own route, and it has an attack row too.
  const zero = await hostGet('/api/lessons/0');
  expect(zero.status, 'GET /api/lessons/0').toBe(200);
  const rows: any[] = [zero.body, ...listed];
  const withAttacks = rows.filter(r => r.built && Array.isArray(r.attacks) && r.attacks.length > 0);
  if (withAttacks.length === 0) throw new NotRun('LESSON_NOT_BUILT', 'no built lesson lists an attack row');
  const missing: string[] = [];
  let total = 0;
  for (const lesson of withAttacks) {
    // The drawer belongs to free play (EventLog.vue), as in app/e2e/lesson-0.spec.ts: pick free mode, then start it.
    await page.getByTestId(`lesson-item-${lesson.lesson}`).click();
    await page.getByTestId('mode-free').click();
    const freeStart = page.getByTestId('free-start');
    if (await freeStart.isVisible().catch(() => false)) await freeStart.click();
    await expect(page.getByTestId('attacks-drawer'), `lesson ${lesson.lesson} shows the attacks drawer`).toBeAttached({ timeout: 30_000 });
    for (const a of lesson.attacks) {
      total++;
      const button = page.getByTestId(`attack-${a.attackId}`);
      try { await expect(button).toHaveCount(1, { timeout: 15_000 }); }
      catch { missing.push(`lesson ${lesson.lesson}: ${a.attackId}`); }
    }
  }
  expect(missing, `${missing.length} of ${total} attack rows have no button`).toEqual([]);
});
