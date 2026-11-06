import { expect, test, type Page } from '@playwright/test'
import { MIN_RATIO, scanPage, setTheme } from './contrast'
import { runFreePlay } from './walk'

// The Message bytes panel on lesson 1 (Steve's run, 2026-11-05): a beginner sees the readable bytes and the bytes on the wire together,
// nothing is lit until he picks a field, and a field lights only its own bytes.
async function pickTextGcm1(page: Page) {
  await runFreePlay(page, 1)
  await page.locator('[data-testid^=diagram-message-]', { hasText: 'TextGcm1' }).first().click()
  await page.getByTestId('inspector-tab-bytes').click()
}
const lit = (page: Page, grid: string) => page.getByTestId(grid).locator('.hb.lit')
const byteText = async (page: Page, from: number, to: number) => {
  let s = ''
  for (let i = from; i < to; i++) s += (await page.getByTestId(`inspector-byte-${i}`).textContent())?.trim()
  return s
}

test('the panel has one name, and the tab and the title both say it', async ({ page }) => {
  await pickTextGcm1(page)
  await expect(page.getByTestId('inspector-tab-bytes')).toHaveText('Message bytes')
  await expect(page.getByTestId('inspector-title')).toHaveText(/message bytes/i)
})

test('before and after show side by side: 64 readable bytes became 96 bytes on the wire', async ({ page }) => {
  await pickTextGcm1(page)
  await expect(page.getByTestId('inspector-before')).toBeVisible()
  await expect(page.getByTestId('inspector-after')).toBeVisible()
  await expect(page.getByTestId('inspector-before-count')).toContainText('64 bytes')
  await expect(page.getByTestId('inspector-after-count')).toContainText('96 bytes')
  await expect(page.getByTestId('inspector-before')).toContainText('Pump four is ok.')
})

test('nothing is lit until a field is picked, and a field lights only its own bytes', async ({ page }) => {
  await pickTextGcm1(page)
  await expect(lit(page, 'inspector-after')).toHaveCount(0)
  await expect(lit(page, 'inspector-before')).toHaveCount(0)
  const nonce = page.getByTestId('inspector-field-row-nonce')
  await expect(nonce).toHaveAttribute('aria-pressed', 'false')
  await nonce.click()
  await expect(nonce).toHaveAttribute('aria-pressed', 'true')
  await expect(lit(page, 'inspector-after')).toHaveCount(12)
  for (const i of [4, 15]) await expect(page.getByTestId(`inspector-byte-${i}`)).toHaveClass(/\blit\b/)
  for (const i of [3, 16]) await expect(page.getByTestId(`inspector-byte-${i}`)).not.toHaveClass(/\blit\b/)
  await nonce.click()
  await expect(lit(page, 'inspector-after')).toHaveCount(0)
})

test('a field value reads the wire bytes at its own offsets', async ({ page }) => {
  await pickTextGcm1(page)
  await expect(page.getByTestId('inspector-field-value-nonce')).toHaveText(await byteText(page, 4, 16))
  await expect(page.getByTestId('inspector-field-value-type')).toHaveText(await byteText(page, 0, 1))
})

test('the cipher field lights the readable bytes it was made from', async ({ page }) => {
  await pickTextGcm1(page)
  await page.getByTestId('inspector-field-row-cipher').click()
  await expect(lit(page, 'inspector-after')).toHaveCount(64)
  await expect(lit(page, 'inspector-before')).toHaveCount(64)
})

test('the eavesdropper gets no readable bytes of a locked message', async ({ page }) => {
  await pickTextGcm1(page)
  await page.getByTestId('view-eavesdropper').click()
  await expect(page.getByTestId('inspector-before')).toHaveCount(0)
  await expect(page.getByTestId('inspector-before-hidden')).toBeVisible()
  await expect(page.getByTestId('inspector-after')).toBeVisible()
})

for (const theme of ['light', 'dark'] as const) {
  test(`lit fields read at ${MIN_RATIO} to 1 in the ${theme} theme`, async ({ page }) => {
    await pickTextGcm1(page)
    await setTheme(page, theme)
    for (const name of ['type', 'length', 'nonce', 'cipher', 'tag']) await page.getByTestId(`inspector-field-row-${name}`).click()
    await page.waitForTimeout(900)
    await page.screenshot({ path: `test-results/bytes-panel-${theme}.png` })
    const s = await scanPage(page)
    expect(s.fails, JSON.stringify(s.fails.slice(0, 5))).toEqual([])
  })
}

// 1080p at 125 percent leaves about 1536 x 760 for the page under the title bar and the menu.
for (const size of [{ width: 1536, height: 760 }, { width: 1920, height: 970 }]) {
  test(`the whole app fits ${size.width} x ${size.height} with no cut edges, and the lane names stay in view`, async ({ page }) => {
    await page.setViewportSize(size)
    await runFreePlay(page, 1)
    const box = await page.evaluate(() => {
      const r = (e: Element) => e.getBoundingClientRect()
      const status = r(document.querySelector('[data-testid=status-bar]')!)
      const panels = [...document.querySelectorAll('.panel, .rail')].map(e => r(e).bottom)
      return { vh: innerHeight, vw: innerWidth, docH: document.documentElement.scrollHeight, docW: document.documentElement.scrollWidth, statusBottom: status.bottom, statusTop: status.top, panelBottom: Math.max(...panels) }
    })
    expect(box.docH, 'page scrolls down').toBeLessThanOrEqual(box.vh)
    expect(box.docW, 'page scrolls sideways').toBeLessThanOrEqual(box.vw)
    expect(box.statusBottom).toBeLessThanOrEqual(box.vh)
    expect(box.panelBottom).toBeLessThanOrEqual(box.statusTop)
    // Scroll the diagram to its end; the lane names must still show at the top.
    const scroller = page.getByTestId('diagram').locator('.diagram-scroll')
    await scroller.evaluate(e => { e.scrollTop = e.scrollHeight })
    await page.waitForTimeout(200)
    const lane = await page.getByTestId('diagram-lane-client').locator('text').boundingBox()
    const view = await scroller.boundingBox()
    expect(lane && view && lane.y >= view.y - 1 && lane.y + lane.height <= view.y + view.height, 'client lane name in view').toBeTruthy()
  })
}
