import { expect, test, type Page } from '@playwright/test'
import { createHash } from 'node:crypto'
import { startOwnHost, type OwnHost } from './own-host'
import { certificatesArePublic, closedToListener, listenerCanMeasure } from '../src/lab'
import { open } from './walk'

// A listener sees the wire and nothing else. This walks every lesson's tabs and events in the Eavesdropper view, and it fails on readable text or key
// bytes on screen that no wire byte in the session holds. Text that really is on the wire stays, because it is in the wire bytes.
let host: OwnHost
test.beforeAll(async () => { host = await startOwnHost() })
test.afterAll(async () => { await host.stop() })

interface Ev { seq: number; type: string; message: string; detail: string; locked: boolean; fields: { name: string; offset: number; length: number; visibleToWire: boolean }[]; plain: string; wire: string; secrets: { name: string; hex: string; holder: string }[] }
interface Finding { what: string; where: string; value: string; from: string }

const textOf = (hex: string) => { let s = ''; for (let i = 0; i + 1 < hex.length; i += 2) s += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16)); return s }
// Runs of 6 or more letters, digits and spaces with a letter in them, and runs of 12 or more digits, which is a card number's shape.
const wordsIn = (text: string) => [
  ...[...text.matchAll(/[A-Za-z0-9 ,.:_-]{6,}/g)].map(m => m[0].trim()).filter(w => w.length >= 6 && /[A-Za-z]/.test(w) && !/^[0-9a-f]+$/i.test(w)),
  ...[...text.matchAll(/\d{12,}/g)].map(m => m[0]),
]
const base64Of = (hex: string) => Buffer.from(hex, 'hex').toString('base64')

// A listener can decode base64 too: a token's claims cross the wire in the clear this way, and lesson 10 teaches that.
const decodedOnWire = (hex: string) => [...textOf(hex).matchAll(/[A-Za-z0-9_-]{16,}/g)].map(m => Buffer.from(m[0], 'base64url').toString('latin1')).join('|')

async function eventsOf(page: Page): Promise<Ev[]> {
  const id = await page.locator('.statusbar').innerText().then(t => /session (?<id>\S+)/.exec(t)?.groups?.id ?? '')
  const r = await fetch(`http://127.0.0.1:${host.port}/api/sessions/${id}/events`, { headers: { Authorization: `Bearer ${host.token}` } })
  const body = (await r.json()) as { events?: any[] } | any[]
  return (Array.isArray(body) ? body : body.events ?? []).map((f: any) => {
    const e = f.event ?? f
    return {
      seq: Number(f.seq ?? e.seq), type: String(e.type ?? ''), message: String(e.message ?? ''), detail: String(e.detail ?? ''),
      fields: e.fields ?? [], locked: (e.fields ?? []).some((x: any) => x.visibleToWire === false), plain: String(e.plain ?? '').toLowerCase(), wire: String(e.wire ?? '').toLowerCase(),
      secrets: (e.secrets ?? []).map((x: any) => ({ name: String(x.name), holder: String(x.holder), hex: String(x.hex ?? '').toLowerCase() })),
    }
  })
}

// An SSH host key crosses in the clear, so its fingerprint follows from the wire. This checks that against the bytes: the name stays forbidden if no wire key hashes to it.
function fingerprintsOnWire(events: Ev[]): Set<string> {
  const out = new Set<string>()
  for (const e of events) for (const f of e.fields) {
    if (f.name !== 'hostKey' || !f.visibleToWire || !e.wire) continue
    const bytes = Buffer.from(e.wire.slice(f.offset * 2, (f.offset + f.length) * 2), 'hex')
    for (const blob of [bytes, bytes.subarray(4)]) out.add('SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, ''))
  }
  return out
}

// Everything the session put on the wire, as hex and as text, is public. Everything else an event holds is forbidden on this screen.
function forbiddenValues(events: Ev[]) {
  const wireHex = events.map(e => e.wire).join('|')
  const wireText = events.map(e => `${textOf(e.wire)}|${decodedOnWire(e.wire)}`).join('|')
  // A token that crosses in the clear makes its claims public, and the measures of those claims name them.
  const tokensPublic = events.some(e => e.wire && e.fields.some(f => /^(?:token|proof)(?:Header|Claims)$/.test(f.name) && f.visibleToWire))
  const publicNames = [...new Set(events.filter(e => e.wire && !e.locked).map(e => e.message)), ...fingerprintsOnWire(events), ...(tokensPublic ? ['token claims', 'proof claims'] : [])]
  const words = new Map<string, string>()
  const hex8 = new Map<string, string>()
  const hex4 = new Map<string, string>()
  const base64 = new Map<string, string>()
  const label = (e: Ev) => `${e.type} ${e.message}`.trim()
  for (const e of events) {
    for (const w of wordsIn(textOf(e.plain))) if (!wireText.includes(w)) words.set(w, label(e))
    // Only the listener's own events have a name it can read: a locked message, or a step inside an endpoint, keeps its name hidden.
    if ((e.locked || !e.wire) && e.message.length >= 4 && !publicNames.some(n => n.includes(e.message))) words.set(e.message, `name of ${label(e)}`)
    // A detail reads key=value;key=value. The keys are the app's own words, and the values are what an event holds.
    if (e.locked || !e.wire) for (const pair of e.detail.split(';')) for (const w of wordsIn(pair.split('=').pop() ?? '')) if (!wireText.includes(w)) words.set(w, `detail of ${label(e)}`)
    // 8-byte windows of readable bytes that no wire holds, at every byte offset.
    for (let i = 0; i + 16 <= e.plain.length; i += 2) { const h = e.plain.slice(i, i + 16); if (!wireHex.includes(h)) hex8.set(h, `plain of ${label(e)}`) }
    if (e.plain.length >= 24 && !wireHex.includes(e.plain)) base64.set(base64Of(e.plain).slice(0, 16), `plain of ${label(e)}, as base64`)
    for (const x of e.secrets) {
      if (x.hex.length < 8 || wireHex.includes(x.hex)) continue
      // The first and last 4 bytes, because a screen can shorten a key to either end.
      hex4.set(x.hex.slice(0, 8), `secret ${x.holder}.${x.name}`)
      hex4.set(x.hex.slice(-8), `secret ${x.holder}.${x.name}`)
      base64.set(base64Of(x.hex).slice(0, 16), `secret ${x.holder}.${x.name}, as base64`)
    }
  }
  return { words, hex8, hex4, base64 }
}

let lastScreen = ''
// The panels, with hidden text, tooltips and spoken labels. Event rows and attack buttons are read on their own terms, so no value can hide behind a label.
// The status bar names the session and the rail names lessons, and neither comes from a message.
const screenText = (page: Page) => page.locator('.main-split').evaluate(root => {
  const parts: string[] = []
  const attrs: string[] = []
  const walk = (n: Node) => {
    if (n.nodeType === 3) { parts.push(n.textContent ?? ''); return }
    if (n.nodeType !== 1) return
    const e = n as Element
    if (e.matches('.log-row, [data-testid^=attack-], select')) return
    for (const a of ['title', 'aria-label']) { const v = e.getAttribute(a); if (v) attrs.push(v) }
    n.childNodes.forEach(walk)
  }
  walk(root)
  return [parts.join(' '), parts.join(''), ...attrs].join('\n')
})

async function scan(page: Page, values: ReturnType<typeof forbiddenValues>, where: string, out: Finding[]) {
  const screen = await screenText(page)
  if (screen === lastScreen) return
  lastScreen = screen
  for (const [w, from] of values.words) if (screen.includes(w)) out.push({ what: 'text', where, value: w.slice(0, 40), from })
  for (const [b, from] of values.base64) if (screen.includes(b)) out.push({ what: 'base64', where, value: b, from })
  // Spaces, colons and dashes are how a screen can format hex, so they go before the search. A window lookup keeps this fast on a long message.
  const packed = screen.toLowerCase().replace(/[\s:\-]/g, '')
  for (let i = 0; i + 8 <= packed.length; i++) {
    const four = values.hex4.get(packed.slice(i, i + 8))
    if (four) out.push({ what: 'hex', where, value: packed.slice(i, i + 8), from: four })
    const eight = i + 16 <= packed.length ? values.hex8.get(packed.slice(i, i + 16)) : undefined
    if (eight) out.push({ what: 'hex', where, value: packed.slice(i, i + 16), from: eight })
  }
}

// The rule (lead, 2026-11-06): lessons 0 to 6 in every suite. All 12 with NETSEC_SWEEP_ALL=1, in Echo's long run and on any PR that touches the Eavesdropper view.
// Lessons 7 to 10 take about 5 minutes each, because each view switch redraws a long diagram.
const LESSONS = process.env.NETSEC_SWEEP_ALL === '1' ? [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11] : [0, 1, 2, 3, 4, 5, 6]
for (const lesson of LESSONS) {
  test(`lesson ${lesson}: the Eavesdropper view shows nothing a listener could not see`, async ({ page }) => {
    test.setTimeout(900_000)
    lastScreen = ''
    await page.setViewportSize({ width: 1440, height: 900 })
    await open(page, host)
    await page.getByTestId(`lesson-item-${lesson}`).click()
    await page.getByTestId('mode-free').click()
    await page.getByTestId('free-start').click()
    // What the screen says before the engine runs is fixed text, unless an event already stored put it there. The session starts held at its first step.
    await expect(page.getByTestId('free-run')).toBeVisible()
    await page.getByTestId('diagram').waitFor()
    const fixedText = await screenText(page)
    const early = (await eventsOf(page)).map(e => `${textOf(e.plain)}|${e.message}|${e.detail}`).join('|')
    await page.getByTestId('free-run').click()
    await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 90_000 })
    const events = await eventsOf(page)
    expect(events.length, 'events from the engine, or this sweep proves nothing').toBeGreaterThan(0)
    const values = forbiddenValues(events)
    for (const w of [...values.words.keys()]) if (fixedText.includes(w) && !early.includes(w)) values.words.delete(w)

    const found: Finding[] = []
    const onWire = events.filter(e => e.type === 'wire.sent')
    // One event per kind: switching views for each one would add many minutes to everyone's suite. Every on-wire row below is still read.
    const insideEndpoint = [...new Map(events.filter(e => e.type !== 'wire.sent' && (e.plain || e.wire || e.secrets.length)).map(e => [`${e.type}|${e.message}`, e])).values()]
    let scanned = 0

    // A step inside an endpoint, a reception among them, has no row in this view, so it is picked as an endpoint would, and the view then switches.
    for (const e of insideEndpoint) {
      await page.getByTestId('view-endpoints').click()
      const row = page.getByTestId(`event-row-${e.seq}`)
      expect(await row.count(), `event ${e.seq} ${e.type} has no row in the Endpoints view`).toBe(1)
      await row.click()
      await page.getByTestId('view-eavesdropper').click()
      await scan(page, values, `event ${e.seq} ${e.type} ${e.message}`, found)
      scanned++
    }

    await page.getByTestId('view-eavesdropper').click()
    const tabs = await page.locator('[data-testid^=inspector-tab-]').evaluateAll(all => all.map(e => e.getAttribute('data-testid')!))
    for (const tab of tabs) {
      await page.getByTestId(tab).click()
      await scan(page, values, tab, found)
    }

    // The log lists on-wire events only, and each row holds only its number, its sender and its type.
    const rows = await page.locator('.log-row').evaluateAll(all => all.map(e => [...e.children].map(c => (c.textContent ?? '').trim())))
    expect(rows.length, 'log rows in this view, one per on-wire event').toBe(onWire.length)
    for (const r of rows) expect(r.length === 3 && /^\d+$/.test(r[0]) && r[2] === 'wire.sent', `a log row holds more than its number, sender and type: ${r.join(' | ')}`).toBeTruthy()

    for (const e of onWire) {
      const row = page.getByTestId(`event-row-${e.seq}`)
      expect(await row.count(), `event ${e.seq} ${e.message} is on the wire and has no row`).toBe(1)
      await row.click()
      const tab = await page.locator('[data-testid^=inspector-tab-].on').evaluateAll(all => all[0]?.getAttribute('data-testid') ?? 'no tab row')
      await scan(page, values, `event ${e.seq} ${e.type} ${e.message} on ${tab}`, found)
      scanned++
    }
    expect(scanned, 'events scanned').toBe(onWire.length + insideEndpoint.length)

    const unique = [...new Map(found.map(f => [`${f.what}|${f.value}`, f])).values()]
    console.log(`lesson ${lesson}: forbids ${values.words.size} texts, ${values.hex8.size} windows, ${values.hex4.size} key ends, ${values.base64.size} base64. ${events.length} events, ${scanned} scanned, ${tabs.length} tabs, ${unique.length} shown`)
    for (const f of unique.slice(0, 12)) console.log(`  SHOWN ${f.what} "${f.value}" from ${f.from}, at ${f.where}`)
    expect(unique, `lesson ${lesson}`).toEqual([])
  })
}

async function runLesson(page: Page, lesson: number) {
  await page.setViewportSize({ width: 1440, height: 900 })
  await open(page, host)
  await page.getByTestId(`lesson-item-${lesson}`).click()
  await page.getByTestId('mode-free').click()
  await page.getByTestId('free-start').click()
  await page.getByTestId('free-run').click()
  await expect(page.getByTestId('engine-state')).toContainText(/finished/, { timeout: 90_000 })
}

// Each closed tab says why, and the same tab still works for an endpoint. The Keys in use strip names key values, so a listener never sees it.
const CLOSED: [number, string, string][] = [
  [4, 'chain', 'The certificates travel locked in this lesson'],
  [6, 'ladder', 'None of them crosses the wire'],
  [9, 'onion', 'A listener sees only the outer bytes'],
  [11, 'timing', 'nothing here crosses a wire'],
]
for (const [lesson, tab, words] of CLOSED) {
  test(`lesson ${lesson}: the ${tab} tab closes to a listener, says why, and opens again for an endpoint`, async ({ page }) => {
    await runLesson(page, lesson)
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

test('lesson 10: the token tab stays open to a listener and says it is public', async ({ page }) => {
  await runLesson(page, 10)
  await page.getByTestId('inspector-tab-token').click()
  await expect(page.getByTestId('inspector-public')).toHaveCount(0)
  await page.getByTestId('view-eavesdropper').click()
  await expect(page.getByTestId('inspector-public')).toContainText('a listener can decode the claims')
  await expect(page.getByTestId('inspector-closed')).toHaveCount(0)
})

test('lesson 1: the listener keeps the repeated-block count, which comes from the ciphertext', async ({ page }) => {
  await runLesson(page, 1)
  await page.getByTestId('inspector-tab-measures').click()
  await page.getByTestId('view-eavesdropper').click()
  await expect(page.getByTestId('measure-panel')).toContainText('locked blocks repeat')
})

test('lesson 2: the avalanche count comes from inside an endpoint, so the listener does not get it', async ({ page }) => {
  await runLesson(page, 2)
  await page.getByTestId('inspector-tab-measures').click()
  await expect(page.getByTestId('avalanche-grid').first()).toBeVisible()
  await page.getByTestId('view-eavesdropper').click()
  await expect(page.getByTestId('avalanche-grid')).toHaveCount(0)
  await expect(page.getByTestId('measure-none')).toContainText('inside an endpoint')
})

test('a locked message keeps its name from the listener', async ({ page }) => {
  await runLesson(page, 1)
  await page.locator('[data-testid^=diagram-message-]', { hasText: 'TextGcm1' }).first().click({ timeout: 8000 })
  await page.getByTestId('inspector-tab-bytes').click()
  await expect(page.getByTestId('inspector')).toContainText('TextGcm1')
  await page.getByTestId('view-eavesdropper').click()
  await expect(page.getByTestId('inspector')).toContainText('Locked message')
  await expect(page.getByTestId('inspector')).not.toContainText('TextGcm1')
})

test('the log lists on-wire events only, and it counts them', async ({ page }) => {
  await runLesson(page, 1)
  const all = await page.locator('.log-row').count()
  await page.getByTestId('view-eavesdropper').click()
  const wire = await page.locator('.log-row').count()
  expect(wire, 'on-wire rows').toBeGreaterThan(0)
  expect(wire, 'fewer rows than the endpoints see').toBeLessThan(all)
  await expect(page.getByTestId('event-log')).toContainText(`${wire} on the wire`)
  await page.getByTestId('view-endpoints').click()
  await expect(page.locator('.log-row')).toHaveCount(all)
})

test('lesson 8: the host key is public, and the client\'s verdict on it is not', async ({ page }) => {
  await runLesson(page, 8)
  await page.getByTestId('inspector-tab-hostkey').click()
  await expect(page.getByTestId('hostkey-status').first()).toBeVisible()
  await page.getByTestId('view-eavesdropper').click()
  await expect(page.getByTestId('hostkey-fingerprint').first()).toBeVisible()
  await expect(page.getByTestId('hostkey-status')).toHaveCount(0)
})

test('lesson 7: the TLS 1.1 certificate crosses in the clear, so the listener sees it, and the screen says it is public', async ({ page }) => {
  await runLesson(page, 7)
  await page.locator('[data-testid^=diagram-message-]', { hasText: 'Certificate' }).first().click({ timeout: 8000 })
  await page.getByTestId('inspector-tab-bytes').click().catch(() => {})
  await page.getByTestId('view-eavesdropper').click()
  await expect(page.getByTestId('inspector-public-bytes')).toContainText('Public')
  await expect(page.getByTestId('inspector-after')).toBeVisible()
})

test('a token that crosses in the clear stays open, and one under a lock closes', () => {
  const f = (name: string, visibleToWire: boolean) => ({ name, offset: 0, length: 1, kind: 'data', visibleToWire, gloss: '' })
  expect(closedToListener('token', [{ type: 'wire.sent', plain: '', wire: 'aa', fields: [f('tokenClaims', true)] } as any])).toBeNull()
  expect(closedToListener('token', [{ type: 'wire.sent', plain: '', wire: 'aa', fields: [f('tokenClaims', false)] } as any])).toContain('locked')
})

test('a measure of token claims shows the listener only while the token crosses in the clear', () => {
  const field = (visibleToWire: boolean) => ({ name: 'tokenClaims', offset: 0, length: 1, kind: 'data', visibleToWire, gloss: '' })
  const claims = { type: 'measure.result', message: 'token claims', detail: '', plain: 'aa', wire: '', fields: [] } as any
  expect(listenerCanMeasure(claims, [claims, { type: 'wire.sent', plain: '', wire: 'aa', fields: [field(true)] } as any])).toBe(true)
  expect(listenerCanMeasure(claims, [claims, { type: 'wire.sent', plain: '', wire: 'aa', fields: [field(false)] } as any])).toBe(false)
})

test('a certificate that crosses the wire in the clear is public, and one that does not is closed', async () => {
  const cert = 'aabbccddeeff00112233'
  const issued = { type: 'ca.certificate.issued', plain: cert, wire: '' } as any
  expect(certificatesArePublic([issued, { type: 'wire.sent', plain: '', wire: `0102${cert}0304` } as any])).toBe(true)
  expect(closedToListener('chain', [issued, { type: 'wire.sent', plain: '', wire: `0102${cert}0304` } as any])).toBeNull()
  expect(certificatesArePublic([issued, { type: 'wire.sent', plain: '', wire: 'ffeeddcc' } as any])).toBe(false)
  expect(closedToListener('chain', [issued])).toContain('locked')
})
