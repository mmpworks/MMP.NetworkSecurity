import { expect, test, type Page } from '@playwright/test'
import { startOwnHost, type OwnHost } from './own-host'
import { certificatesArePublic, closedToListener } from '../src/lab'
import { open } from './walk'

// A listener sees the wire and nothing else. This walks every lesson's tabs and events in the Eavesdropper view, and it fails on readable text or key
// bytes on screen that no wire byte in the session holds. Text that really is on the wire stays, because it is in the wire bytes.
let host: OwnHost
test.beforeAll(async () => { host = await startOwnHost() })
test.afterAll(async () => { await host.stop() })

interface Ev { seq: number; type: string; message: string; actor: string; check: string; plain: string; wire: string; secrets: { name: string; hex: string; holder: string }[] }
interface Finding { what: string; where: string; value: string; from: string }

const textOf = (hex: string) => { let s = ''; for (let i = 0; i + 1 < hex.length; i += 2) s += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16)); return s }
// Runs of 6 or more letters, digits and spaces, with at least one letter: words a learner would read.
const wordsIn = (hex: string) => [...textOf(hex).matchAll(/[A-Za-z0-9 ,.:_-]{6,}/g)].map(m => m[0].trim()).filter(w => w.length >= 6 && /[A-Za-z]/.test(w) && !/^[0-9a-f]+$/i.test(w))

async function eventsOf(page: Page): Promise<Ev[]> {
  const id = await page.locator('.statusbar').innerText().then(t => /session (?<id>\S+)/.exec(t)?.groups?.id ?? '')
  const r = await fetch(`http://127.0.0.1:${host.port}/api/sessions/${id}/events`, { headers: { Authorization: `Bearer ${host.token}` } })
  const body = (await r.json()) as { events?: any[] } | any[]
  return (Array.isArray(body) ? body : body.events ?? []).map((f: any) => {
    const e = f.event ?? f
    return { seq: Number(f.seq ?? e.seq), type: String(e.type ?? ''), message: String(e.message ?? ''), actor: String(e.actor ?? ''), check: String(e.check?.name ?? ''), plain: String(e.plain ?? '').toLowerCase(), wire: String(e.wire ?? '').toLowerCase(), secrets: (e.secrets ?? []).map((s: any) => ({ name: String(s.name), holder: String(s.holder), hex: String(s.hex ?? '').toLowerCase() })) }
  })
}

// Everything the session put on the wire, as hex and as text. A value found here is public.
function forbiddenValues(events: Ev[]) {
  const wireHex = events.map(e => e.wire).join('|')
  // The event log names each event's type, actor and check. Those are labels, so a word that is also a label proves nothing.
  const wireText = events.map(e => `${textOf(e.wire)}|${e.type}|${e.actor}|${e.check}`).join('|')
  const words = new Map<string, string>()
  const hexes = new Map<string, string>()
  for (const e of events) {
    for (const w of wordsIn(e.plain)) if (!wireText.includes(w)) words.set(w, `${e.type} ${e.message}`.trim())
    // 8-byte windows of readable bytes that no wire holds.
    for (let i = 0; i + 16 <= e.plain.length; i += 16) { const h = e.plain.slice(i, i + 16); if (!wireHex.includes(h)) hexes.set(h, `plain of ${e.type} ${e.message}`.trim()) }
    for (const s of e.secrets) if (s.hex.length >= 16 && !wireHex.includes(s.hex.slice(0, 16))) hexes.set(s.hex.slice(0, 16), `secret ${s.holder}.${s.name}`)
  }
  return { words, hexes }
}

let lastScreen = ''
async function scan(page: Page, values: ReturnType<typeof forbiddenValues>, where: string, out: Finding[]) {
  // The panels only: the status bar names the session, and the rail names lessons, and neither comes from a message.
  const screen = await page.locator('.main-split').evaluate(e => (e as HTMLElement).innerText)
  if (screen === lastScreen) return
  lastScreen = screen
  const packed = screen.toLowerCase().replace(/\s+/g, '')
  for (const [w, from] of values.words) if (screen.includes(w)) out.push({ what: 'text', where, value: w.slice(0, 40), from })
  for (const [h, from] of values.hexes) if (packed.includes(h)) out.push({ what: 'hex', where, value: h, from })
}

for (let lesson = 0; lesson <= 11; lesson++) {
  test(`lesson ${lesson}: the Eavesdropper view shows nothing a listener could not see`, async ({ page }) => {
    test.setTimeout(240_000)
    lastScreen = ''
    await page.setViewportSize({ width: 1440, height: 900 })
    await open(page, host)
    await page.getByTestId(`lesson-item-${lesson}`).click()
    await page.getByTestId('mode-free').click()
    await page.getByTestId('free-start').click()
    await page.getByTestId('free-run').click()
    await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 90_000 })
    const events = await eventsOf(page)
    const values = forbiddenValues(events)
    await page.getByTestId('view-eavesdropper').click()

    // Attack buttons are labels too, and the lesson shows them whichever view is on.
    const labels = (await page.locator('[data-testid^=attack-]').allInnerTexts()).join('|')
    for (const w of [...values.words.keys()]) if (labels.includes(w)) values.words.delete(w)
    const found: Finding[] = []
    const tabs = await page.locator('[data-testid^=inspector-tab-]').evaluateAll(all => all.map(e => e.getAttribute('data-testid')!))
    for (const tab of tabs) {
      await page.getByTestId(tab).click()
      await scan(page, values, tab, found)
    }
    const withBytes = events.filter(e => e.plain || e.wire || e.secrets.length)
    for (const e of withBytes) {
      const row = page.getByTestId(`event-row-${e.seq}`)
      if (!(await row.count())) continue
      await row.click()
      // A lesson with one view has no tab row, so this reads the tab without waiting for one.
      const tab = await page.locator('[data-testid^=inspector-tab-].on').evaluateAll(all => all[0]?.getAttribute('data-testid') ?? 'no tab row')
      await scan(page, values, `event ${e.seq} ${e.type} ${e.message} on ${tab}`, found)
    }
    const unique = [...new Map(found.map(f => [`${f.what}|${f.value}`, f])).values()]
    console.log(`lesson ${lesson}: ${values.words.size} texts and ${values.hexes.size} hex values not on the wire, ${events.length} events (${withBytes.length} with bytes), ${tabs.length} tabs, ${unique.length} shown`)
    for (const f of unique.slice(0, 12)) console.log(`  SHOWN ${f.what} "${f.value}" from ${f.from}, at ${f.where}`)
    expect(unique, `lesson ${lesson}`).toEqual([])
  })
}

// Each closed tab says why, and the same tab still works for an endpoint. The Keys in use strip names key values, so a listener never sees it.
const CLOSED: [number, string, string][] = [
  [4, 'chain', 'The certificates travel locked in this lesson'],
  [6, 'ladder', 'None of them crosses the wire'],
  [10, 'token', 'The token and its claims travel locked'],
  [11, 'timing', 'Nothing here crosses a wire'],
]
for (const [lesson, tab, words] of CLOSED) {
  test(`lesson ${lesson}: the ${tab} tab closes to a listener, says why, and opens again for an endpoint`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await open(page, host)
    await page.getByTestId(`lesson-item-${lesson}`).click()
    await page.getByTestId('mode-free').click()
    await page.getByTestId('free-start').click()
    await page.getByTestId('free-run').click()
    await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 90_000 })
    await page.getByTestId(`inspector-tab-${tab}`).click()
    await expect(page.getByTestId('inspector-closed')).toHaveCount(0)
    if (lesson !== 11) await expect(page.getByTestId('keys-in-use')).toBeVisible()
    await page.getByTestId('view-eavesdropper').click()
    await expect(page.getByTestId('inspector-closed')).toContainText(words)
    await expect(page.getByTestId('keys-in-use')).toHaveCount(0)
    await page.getByTestId('view-endpoints').click()
    await expect(page.getByTestId('inspector-closed')).toHaveCount(0)
  })
}

test('lesson 7: the TLS 1.1 certificate crosses in the clear, so the listener sees it, and the screen says it is public', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await open(page, host)
  await page.getByTestId('lesson-item-7').click()
  await page.getByTestId('mode-free').click()
  await page.getByTestId('free-start').click()
  await page.getByTestId('free-run').click()
  await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 90_000 })
  await page.locator('[data-testid^=diagram-message-]', { hasText: 'Certificate' }).first().click({ timeout: 8000 })
  await page.getByTestId('inspector-tab-bytes').click().catch(() => {})
  await page.getByTestId('view-eavesdropper').click()
  await expect(page.getByTestId('inspector-public-bytes')).toContainText('Public')
  await expect(page.getByTestId('inspector-after')).toBeVisible()
})

test('a certificate that crosses the wire in the clear is public, and one that does not is closed', async () => {
  const cert = 'aabbccddeeff00112233'
  const issued = { type: 'ca.certificate.issued', plain: cert, wire: '' } as any
  expect(certificatesArePublic([issued, { type: 'wire.sent', plain: '', wire: `0102${cert}0304` } as any])).toBe(true)
  expect(closedToListener('chain', [issued, { type: 'wire.sent', plain: '', wire: `0102${cert}0304` } as any])).toBeNull()
  expect(certificatesArePublic([issued, { type: 'wire.sent', plain: '', wire: 'ffeeddcc' } as any])).toBe(false)
  expect(closedToListener('chain', [issued])).toContain('locked')
})
