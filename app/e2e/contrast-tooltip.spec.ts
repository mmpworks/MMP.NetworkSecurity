import { expect, test, type Page } from '@playwright/test'
import { contrastOf, MIN_RATIO, setTheme } from './contrast'
import { startTour } from './walk'

// Bug: the glossary tooltip showed dark text on a dark box (Steve's screenshot, lesson 1, step 3, the term GCM).
// The text must reach 4.5 to 1 on its box in every theme.
async function toStep(page: Page, id: string) {
  for (let i = 0; i < 12; i++) {
    if ((await page.getByTestId('tour-step-id').textContent()) === id) return
    const next = page.getByTestId('tour-next')
    if (await next.isDisabled()) { const t = page.getByTestId('tour-try-it-action'); if (await t.isVisible()) await t.click() }
    await expect(next).toBeEnabled()
    await next.click()
  }
  throw new Error(`step ${id} not reached`)
}

for (const theme of ['dark', 'light'] as const) {
  test(`the GCM tooltip reads at ${MIN_RATIO} to 1 or better in the ${theme} theme`, async ({ page }) => {
    await startTour(page, 1)
    await setTheme(page, theme)
    await toStep(page, 'L1-S03')
    await page.getByTestId('term-gcm').hover()
    const tip = page.locator('[data-testid="term-popover-short"]:visible')
    await expect(tip).toBeVisible()
    await page.waitForTimeout(400)
    const c = await contrastOf(tip)
    expect(c.ratio, `tooltip text ${c.fg} on ${c.bg}`).toBeGreaterThanOrEqual(MIN_RATIO)
  })
}
