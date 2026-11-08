import { expect, test } from '@playwright/test'
import { heldAt } from '../src/secrets'
import type { TraceEvent } from '../src/types'
import { open } from './walk'

// Pure checks of what each side holds at a picked event. The engine runs client and server on 2 threads, so the order of events
// across the 2 sides changes from run to run. Within one side the order is stable. The event shapes are lesson 1's (seed 20261105).
const ev = (seq: number, actor: string, type: string, p: Partial<TraceEvent> = {}): TraceEvent => ({
  seq, eventId: '', streamId: `s/${actor}`, sessionId: 's', traceId: '', hop: '', actor, from: '', to: '', type, message: '', step: '',
  wire: '', plain: '', fields: [], secrets: [], check: null, waiting: '', typeId: '', version: 0, provider: '', detail: '', ...p,
} as TraceEvent)
const key = (holder: string, name: string) => ({ holder, name, hex: 'aa'.repeat(16), derivedFrom: [], fingerprint: 'fp:aa', length: 16, hidden: '' })
const held = (events: TraceEvent[], upTo: number) => heldAt(events, upTo).map(r => `${r.holder}.${r.name}`).sort()

// Lesson 1 as recorded on most runs: both sides load the AES key, then the client sends TextGcm1 (seq 8).
const recorded = (): TraceEvent[] => [
  ev(2, 'server', 'secret.derived', { secrets: [key('server', 'aes.key')] }),
  ev(3, 'client', 'secret.derived', { secrets: [key('client', 'aes.key')] }),
  ev(4, 'server', 'keys.installed'),
  ev(5, 'server', 'state.waiting'),
  ev(6, 'client', 'keys.installed'),
  ev(7, 'client', 'aes.message.sent', { message: 'TextGcm1' }),
  ev(8, 'client', 'wire.sent', { from: 'client', to: 'server', message: 'TextGcm1' }),
  ev(9, 'server', 'wire.received', { from: 'client', to: 'server' }),
]

test('at TextGcm1 both sides hold the AES key, in the order most runs record', () => {
  expect(held(recorded(), 8)).toEqual(['client.aes.key', 'server.aes.key'])
})

// The flip: a slow server thread loads its key after the client has already sent TextGcm1. The server still loads the key before
// any message reaches it, so at TextGcm1 it holds the key. Seen as bytes-grid.spec.ts:209 failing once in a full suite run (#297).
test('at TextGcm1 both sides hold the AES key when the server loads it after the client sends', () => {
  const flipped = recorded().map(e => (e.seq === 2 ? { ...e, seq: 8.5 } : e)).sort((a, b) => a.seq - b.seq).map((e, i) => ({ ...e, seq: i + 1 }))
  const at = flipped.find(e => e.type === 'wire.sent')!.seq
  expect(flipped.findIndex(e => e.secrets.some(s => s.holder === 'server')), 'the server key comes after the send').toBeGreaterThan(flipped.findIndex(e => e.type === 'wire.sent'))
  expect(held(flipped, at)).toEqual(['client.aes.key', 'server.aes.key'])
})

// Lesson 7's decrypt-recording run: after both recorded runs end, the attacker opens the recording with the stolen key, on its own
// stream, with no wire event (Lesson07Tls11.cs). The attacker must hold nothing at the start and the opened secrets only at the end.
test('a side with no wire event holds its secrets only from their own events', () => {
  const events = [
    ev(1, 'client', 'secret.derived', { secrets: [key('client', 'master_secret')] }),
    ev(2, 'client', 'wire.sent', { from: 'client', to: 'server' }),
    ev(3, 'server', 'wire.received', { from: 'client', to: 'server' }),
    ev(4, 'server', 'secret.derived', { secrets: [key('server', 'master_secret')] }),
    ev(5, 'attacker', 'secret.derived', { secrets: [key('attacker', 'master_secret')] }),
    ev(6, 'attacker', 'secret.derived', { secrets: [key('attacker', 'app_key')] }),
  ]
  expect(held(events, 1), 'the attacker holds nothing at the start').toEqual(['client.master_secret'])
  expect(held(events, 4), 'nor before it opens the recording').toEqual(['client.master_secret', 'server.master_secret'])
  expect(held(events, 6), 'and the opened secrets at the end').toEqual(['attacker.app_key', 'attacker.master_secret', 'client.master_secret', 'server.master_secret'])
})

// The same check on the real L7 decrypt-recording run, played from the attack index.
test('in the real L7 decrypt-recording run, the attacker holds nothing at the first event and the opened secrets at the last', async ({ page }) => {
  await open(page)
  await page.getByTestId('attack-index-open').click()
  await page.getByTestId('attack-row-L7-decrypt-recording').click()
  // The row opens the two-run layout. The attacked run's own panes, with the event log and the secrets, open from its session tab.
  await expect(page.getByTestId('two-run')).toBeVisible({ timeout: 90_000 })
  await expect(page.getByTestId('two-run-running'), 'both runs finish').toHaveCount(0, { timeout: 90_000 })
  await page.getByTestId('two-run-back').click()
  await page.getByTestId('lesson-item-7').click()
  await page.locator('.stab', { hasText: 'attack: L7-decrypt-recording' }).click()
  const rows = page.locator('[data-testid^="event-row-"]')
  const attacker = page.locator('[data-testid^="secret-row-attacker-"]')
  await rows.first().click()
  await expect(page.getByTestId('secrets-panel')).toBeVisible()
  await expect(attacker, 'the attacker holds nothing at the first event').toHaveCount(0)
  await rows.last().click()
  await expect(attacker.first(), 'the attacker holds the opened secrets at the last event').toBeVisible()
  expect(await attacker.count(), 'premaster, master and the write keys').toBeGreaterThan(1)
})

// A key a side makes after a message reached it depends on that message, so it shows only from its own event (lesson 3's shape).
test('a key a side makes after its first wire event shows only from its own event', () => {
  const events = [
    ev(1, 'client', 'kex.share.computed', { secrets: [key('client', 'x25519.private')] }),
    ev(2, 'client', 'wire.sent', { from: 'client', to: 'server' }),
    ev(3, 'server', 'wire.received', { from: 'client', to: 'server' }),
    ev(4, 'server', 'kex.share.computed', { secrets: [key('server', 'x25519.private')] }),
  ]
  expect(held(events, 3)).toEqual(['client.x25519.private'])
  expect(held(events, 4)).toEqual(['client.x25519.private', 'server.x25519.private'])
})
