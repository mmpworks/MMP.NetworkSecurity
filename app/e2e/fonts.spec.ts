import { expect, test } from '@playwright/test'
import { startOwnHost, type OwnHost } from './own-host'
import { open } from './walk'

// The app works offline. A learner may have no network, so no font and no other request may leave this machine.
let host: OwnHost
test.beforeAll(async () => { host = await startOwnHost() })
test.afterAll(async () => { await host.stop() })

test('the 3 fonts load from the app, and no request leaves this machine', async ({ page }) => {
  const away: string[] = []
  const fonts: string[] = []
  page.on('request', r => {
    const u = new URL(r.url())
    if (u.protocol === 'data:' || u.protocol === 'blob:') return
    if (!['localhost', '127.0.0.1'].includes(u.hostname)) away.push(r.url())
    if (r.resourceType() === 'font') fonts.push(u.pathname)
  })
  await open(page, host)
  await page.getByTestId('lesson-item-1').click()
  await page.getByTestId('mode-free').click()
  await page.getByTestId('free-start').click()
  await page.getByTestId('free-run').click()
  await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 60_000 })
  await page.evaluate(() => document.fonts.ready)
  const loaded = await page.evaluate(() => [...document.fonts].filter(f => f.status === 'loaded').map(f => f.family.replace(/["']/g, '')))
  expect(away, 'requests that left this machine').toEqual([])
  for (const family of ['Atkinson Hyperlegible', 'Familjen Grotesk', 'JetBrains Mono']) expect(loaded, `${family} loaded`).toContain(family)
  expect(fonts.length, 'font files fetched from the app').toBeGreaterThan(0)
})
