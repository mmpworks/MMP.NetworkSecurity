import { expect, test, type Page } from '@playwright/test'
import { open } from './walk'

// The shell: 3 named regions, one row of top-bar controls, and the controls that must stay in view at every window size.
const SIZES = [{ width: 1440, height: 770 }, { width: 1280, height: 640 }]

const barRows = (page: Page) => page.getByTestId('top-bar').evaluate(bar => {
  const middles = [...bar.children].filter(e => e.getBoundingClientRect().height > 0).map(e => { const b = e.getBoundingClientRect(); return Math.round(b.top + b.height / 2) })
  return Math.max(...middles) - Math.min(...middles) <= 4 ? 1 : 2
})

for (const size of SIZES) {
  test(`at ${size.width} x ${size.height} the top bar keeps one row, a Target device label, and OS transport`, async ({ page }) => {
    await page.setViewportSize(size)
    await open(page)
    for (const id of ['top-bar', 'lesson-rail', 'workspace', 'transport-switch', 'target-select', 'settings-button', 'security-setup-button', 'show-keys-switch']) await expect(page.getByTestId(id)).toBeVisible()
    await expect(page.getByTestId('top-bar').locator('label.field')).toContainText('Target device')
    expect(await barRows(page)).toBe(1)
    const overflow = await page.getByTestId('top-bar').evaluate(bar => bar.scrollWidth - bar.clientWidth)
    expect(overflow, 'the top bar scrolls sideways').toBeLessThanOrEqual(0)
    const spare = await page.getByTestId('top-bar').locator('.v-spacer').evaluate(e => e.getBoundingClientRect().width)
    expect(spare, 'room for the Security setup badge and a longer key count').toBeGreaterThanOrEqual(30)
  })
}

test('Settings holds speed, theme and keyboard keys, and closes on Escape and on an outside click', async ({ page }) => {
  await open(page)
  const menu = page.getByTestId('settings-menu')
  const button = page.getByTestId('settings-button')
  await expect(menu).toBeHidden()
  await button.click()
  await expect(button).toHaveAttribute('aria-expanded', 'true')
  for (const id of ['speed-select', 'theme-select', 'shortcuts-button']) await expect(menu.getByTestId(id)).toBeVisible()
  const box = (await menu.boundingBox())!
  expect(box.x + box.width, 'the menu stays inside the window').toBeLessThanOrEqual(page.viewportSize()!.width)
  await page.keyboard.press('Escape')
  await expect(menu).toBeHidden()
  await expect(button).toBeFocused()
  await button.click()
  await page.getByTestId('workspace').click({ position: { x: 5, y: 5 } })
  await expect(menu).toBeHidden()
  await button.click()
  await page.getByTestId('shortcuts-button').click()
  await expect(page.getByTestId('shortcut-sheet')).toBeVisible()
  await expect(menu).toBeHidden()
})

test('the overlay layer sits outside the workspace, so the walk\'s clip cannot cut a tip', async ({ page }) => {
  await open(page)
  const outside = await page.getByTestId('overlay-layer').evaluate(e => !e.closest('[data-testid=workspace]') && getComputedStyle(e).position === 'fixed' && getComputedStyle(e).pointerEvents === 'none')
  expect(outside).toBe(true)
})
