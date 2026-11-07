import { _electron as electron, expect, test, type Page } from '@playwright/test'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { runFreePlay, walkTourUntil } from './walk'

// The Message bytes panel at the sizes a 1080p screen gives at 125 percent. A page that fits its window can still cut the panel inside it, so this
// measures the panel: every field row in view, and no hex row or column cut. L1-S05 tells the learner to find the tag, the last field of TextGcm1.
// Headless Chromium draws no scrollbars and Electron does, so one test measures real Electron.
async function pickTextGcm1(page: Page) {
  await page.locator('[data-testid^=diagram-message-]', { hasText: 'TextGcm1' }).first().click()
  await page.getByTestId('inspector-tab-bytes').click()
  await page.waitForTimeout(900)
}

const measure = (page: Page) => page.evaluate(() => {
  const box = (e: Element) => e.getBoundingClientRect()
  const list = box(document.querySelector('.field-list')!)
  const rows = [...document.querySelectorAll('.field-list .field-row')].map(box)
  const grids = [...document.querySelectorAll('.hex-scroll')].map(e => ({ shown: e.clientHeight, whole: e.scrollHeight, shownWide: e.clientWidth, wholeWide: e.scrollWidth }))
  const middles = [...document.querySelectorAll('.topbar > *')].map(e => Math.round(box(e).top + box(e).height / 2))
  const rail = document.querySelector('.rail')!
  return { railWhole: rail.scrollHeight, railShown: rail.clientHeight, pageBar: innerWidth - document.documentElement.clientWidth, fields: rows.length, fieldsInView: rows.filter(r => r.top >= list.top - 1 && r.bottom <= list.bottom + 1).length, grids, barRows: new Set(middles).size }
})

function expectWholePanel(m: Awaited<ReturnType<typeof measure>>) {
  expect(m.fieldsInView, 'field rows in view').toBe(5)
  expect(m.grids, 'the Before and After grids').toHaveLength(2)
  for (const g of m.grids) {
    expect(g.whole, 'a hex row is cut').toBeLessThanOrEqual(g.shown)
    expect(g.wholeWide, 'a hex column is cut').toBeLessThanOrEqual(g.shownWide)
  }
  expect(m.barRows, 'rows of top-bar buttons').toBe(1)
  expect(m.railWhole, 'a lesson is cut from the rail').toBeLessThanOrEqual(m.railShown)
  expect(m.pageBar, 'a scrollbar on the page edge').toBe(0)
}

for (const size of [{ width: 1536, height: 760 }, { width: 1440, height: 760 }, { width: 1440, height: 900 }]) {
  test(`at ${size.width} x ${size.height} TextGcm1 shows all 5 fields and no cut row`, async ({ page }) => {
    await page.setViewportSize(size)
    await runFreePlay(page, 1)
    await pickTextGcm1(page)
    expectWholePanel(await measure(page))
  })
}

test('a view switch turns off a lit field, so a hidden row can never stay lit', async ({ page }) => {
  await runFreePlay(page, 1)
  await pickTextGcm1(page)
  await page.getByTestId('inspector-field-row-cipher').click()
  await expect(page.getByTestId('inspector-after').locator('.hb.lit')).toHaveCount(64)
  await page.getByTestId('view-eavesdropper').click()
  await expect(page.getByTestId('inspector-field-row-cipher')).toHaveCount(0)
  await expect(page.getByTestId('inspector-after').locator('.hb.lit')).toHaveCount(0)
})

const FIT_TOKEN = 'bytes-fit-token'
test('real Electron at 1440 x 770 shows all 5 fields and no cut row, in Free play and on the first tour step that shows TextGcm1', async ({}, testInfo) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-e2e-fit-'))
  const app = await electron.launch({ args: ['.'], cwd: path.join(__dirname, '..'), env: { ...process.env, NETSEC_PORT: '5192', NETSEC_TOKEN: FIT_TOKEN, NETSEC_SECURITY_DIR: dir } })
  try {
    const win = await app.firstWindow()
    await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].setContentSize(1440, 770))
    await win.reload()
    await expect(win.getByTestId('host-chip')).toContainText(/connected/i, { timeout: 60_000 })
    await win.getByTestId('lesson-item-1').click()
    await win.getByTestId('mode-free').click()
    await win.getByTestId('free-start').click()
    await win.getByTestId('free-run').click()
    await expect(win.getByTestId('engine-state')).toContainText(/finished/, { timeout: 60_000 })
    await pickTextGcm1(win)
    expectWholePanel(await measure(win))

    await win.reload()
    await expect(win.getByTestId('host-chip')).toContainText(/connected/i, { timeout: 60_000 })
    await win.getByTestId('lesson-item-1').click()
    await win.getByRole('button', { name: /start tour/i }).click()
    await walkTourUntil(win, 'the 5 fields of TextGcm1', async () => (await win.locator('.field-list .field-row').count()) === 5)
    await win.waitForTimeout(1500)
    expectWholePanel(await measure(win))
  } catch (e) {
    // A Playwright trace holds no snapshots of an Electron window, so a failure saves what the window showed and what the Host holds.
    // Host holds TextGcm1 and the screen does not: a delivery fault. Host lacks it: the engine or the session start. The catch must keep the real error.
    const win = await app.firstWindow().catch(() => null)
    if (win) {
      const text = (id: string) => win.getByTestId(id).first().innerText({ timeout: 2000 }).catch(() => 'absent')
      await win.screenshot({ path: testInfo.outputPath('electron-at-failure.png') }).catch(() => {})
      const shown = await win.locator('.statusbar').innerText({ timeout: 2000 }).catch(() => 'no status bar')
      const session = /session (?<id>\S+)/.exec(shown)?.groups?.id ?? ''
      const host = (p: string) => fetch(`http://127.0.0.1:5192${p}`, { headers: { Authorization: `Bearer ${FIT_TOKEN}` } }).then(r => r.json()).catch(() => null)
      const body = session ? await host(`/api/sessions/${session}/events`) : null
      const held: any[] = Array.isArray(body) ? body : body?.events ?? []
      const report = {
        step: await text('tour-step-id'), nextReason: await text('next-reason'), engine: await text('engine-state'), shown: shown.replace(/\s+/g, ' '),
        hostEvents: held.length, hostHasTextGcm1: held.some(f => (f.event ?? f).message === 'TextGcm1'),
        screenArrows: await win.locator('[data-testid^=diagram-message-]').count().catch(() => -1),
        droppedEvents: (await host('/api/health'))?.droppedEvents ?? 'no answer',
      }
      await testInfo.attach('electron-report', { body: JSON.stringify(report) })
      console.log(`electron report at failure: ${JSON.stringify(report)}`)
    }
    throw e
  } finally { await app.close() }
})
