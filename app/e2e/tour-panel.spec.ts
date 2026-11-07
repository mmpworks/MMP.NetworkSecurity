import { expect, test } from '@playwright/test'
import { startTour, tourIds } from './walk'

// The Tour panel's footer: Next and its reason stay on screen at every lesson 1 step, however long the step's words are.
for (const size of [{ width: 1440, height: 770 }, { width: 1280, height: 640 }]) {
  test(`at ${size.width} x ${size.height} the footer stays on screen for every lesson 1 step`, async ({ page }) => {
    test.setTimeout(180_000)
    await page.setViewportSize(size)
    await startTour(page, 1)
    const ids = tourIds(1)
    await expect(page.getByTestId('tour-steps-bar').locator('i')).toHaveCount(ids.length)
    for (let i = 0; i < ids.length; i++) {
      await expect(page.getByTestId('tour-step-id')).toHaveText(ids[i], { timeout: 30_000 })
      await expect(page.getByTestId('tour-progress')).toHaveText(`Step ${i + 1} of ${ids.length}`)
      await expect(page.getByTestId('tour-steps-bar').locator('i.now')).toHaveCount(1)
      const next = page.getByTestId('tour-next')
      const fit = await page.getByTestId('tour-panel').evaluate(panel => {
        const foot = panel.querySelector('.tour-foot')!.getBoundingClientRect()
        const whole = panel.getBoundingClientRect()
        return { inPanel: foot.bottom <= whole.bottom + 1 && foot.top >= whole.top, inWindow: foot.bottom <= innerHeight, panelScroll: panel.scrollHeight - panel.clientHeight }
      })
      expect(fit.inPanel, `${ids[i]}: the footer is inside the panel`).toBe(true)
      expect(fit.inWindow, `${ids[i]}: the footer is inside the window`).toBe(true)
      expect(fit.panelScroll, `${ids[i]}: only the step's words scroll`).toBeLessThanOrEqual(0)
      if (await next.isDisabled()) {
        const tryIt = page.getByTestId('tour-try-it-action')
        if (await tryIt.isVisible()) {
          await expect(page.getByTestId('next-reason')).not.toHaveText('')
          await tryIt.click()
        }
      }
      await expect(next, `Next at ${ids[i]}`).toBeEnabled({ timeout: 45_000 })
      if (i < ids.length - 1) await next.click()
    }
  })
}
