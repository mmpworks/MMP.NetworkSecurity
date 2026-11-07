import { expect, test } from '@playwright/test'
import { bytesView } from '../src/bytes'
import type { TraceEvent, TraceField } from '../src/types'
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { fitWindow } = require('../electron/window-size.cjs') as { fitWindow: (area: { x: number; y: number; width: number; height: number }) => { x: number; y: number; width: number; height: number } }

// Pure checks of the Message bytes layout and the window size. Shapes copied from the lesson 1 trace (TextGcm1, seed 20261105).
const f = (name: string, offset: number, length: number, kind: TraceField['kind'], visibleToWire = true): TraceField => ({ name, offset, length, kind, visibleToWire, gloss: '' })
const ev = (p: Partial<TraceEvent>): TraceEvent => ({
  seq: 1, eventId: '', streamId: 's/client/aes', sessionId: 's', traceId: '', hop: '', actor: 'client', from: 'client', to: 'server', type: 'wire.sent', message: 'm', step: '',
  wire: '', plain: '', fields: [], secrets: [], check: null, waiting: '', detail: '', ...p,
})
const hexOf = (n: number, b: number) => b.toString(16).padStart(2, '0').repeat(n)
const gcm = ev({
  message: 'TextGcm1',
  plain: hexOf(64, 0x50),
  wire: '01' + '000060' + hexOf(12, 0xaa) + hexOf(64, 0xcc) + hexOf(16, 0xee),
  fields: [f('type', 0, 1, 'header'), f('length', 1, 3, 'length'), f('nonce', 4, 12, 'random'), f('cipher', 16, 64, 'cipher', false), f('tag', 80, 16, 'mac')],
})

test('an encrypted message: fields sit on the wire bytes, and the readable bytes became the cipher span', () => {
  const v = bytesView(gcm, 'endpoints')
  expect(v.before?.hex.length).toBe(128)
  expect(v.after?.hex.length).toBe(192)
  expect(v.fieldsOn).toBe('after')
  expect(v.source).toEqual({ offset: 16, length: 64 })
})

test('the eavesdropper sees no readable bytes of a locked message', () => {
  const v = bytesView(gcm, 'eavesdropper')
  expect(v.before).toBeNull()
  expect(v.after?.hex.length).toBe(192)
})

test('a message sent in the clear shows one grid, with the fields on it', () => {
  const hex = '01000b' + hexOf(11, 0x41)
  const v = bytesView(ev({ plain: hex, wire: hex, fields: [f('type', 0, 1, 'header'), f('length', 1, 2, 'length'), f('body', 3, 11, 'data')] }), 'endpoints')
  expect(v.before).toBeNull()
  expect(v.after?.hex).toBe(hex)
  expect(v.fieldsOn).toBe('after')
})

test('a message whose payload shows in the wire links the payload to its place', () => {
  const plain = hexOf(30, 0x41)
  const wire = '02' + '000040' + plain + hexOf(34, 0x99)
  const v = bytesView(ev({ plain, wire, fields: [f('type', 0, 1, 'header'), f('length', 1, 3, 'length'), f('body', 4, 30, 'data'), f('seal', 34, 34, 'mac')] }), 'endpoints')
  expect(v.fieldsOn).toBe('after')
  expect(v.source).toEqual({ offset: 4, length: 30 })
})

test('fields that describe the inner message sit on the readable bytes', () => {
  // TLS 1.3 Finished: the fields describe the 36 readable bytes inside a 58-byte record.
  const v = bytesView(ev({ plain: hexOf(36, 0x14), wire: hexOf(58, 0x17), fields: [f('msg_type', 0, 1, 'header', false), f('length', 1, 3, 'length', false), f('verify_data', 4, 32, 'mac', false)] }), 'endpoints')
  expect(v.fieldsOn).toBe('before')
})

test('an engine event with no wire bytes shows only the fields that fit its bytes', () => {
  const v = bytesView(ev({ type: 'aes.message.sent', plain: hexOf(64, 0x50), wire: '', fields: gcm.fields }), 'endpoints')
  expect(v.after).toBeNull()
  expect(v.before?.hex.length).toBe(128)
  expect(v.fields).toEqual([])
})

test('a step inside an endpoint shows the eavesdropper nothing', () => {
  // Lesson 7, tls.record.received: the receiver's readable text, with no wire bytes.
  const received = ev({ type: 'tls.record.received', plain: hexOf(19, 0x68), wire: '', fields: [f('application_data', 0, 19, 'data', false)] })
  const v = bytesView(received, 'eavesdropper')
  expect(v.before).toBeNull()
  expect(v.after).toBeNull()
  expect(v.fields).toEqual([])
  expect(v.neverOnWire).toBe(true)
  expect(bytesView(received, 'endpoints').before?.hex.length).toBe(38)
})

test('the window fits the screen work area of a 1080p screen at 100, 125 and 150 percent', () => {
  for (const area of [{ x: 0, y: 0, width: 1920, height: 1032 }, { x: 0, y: 0, width: 1536, height: 824 }, { x: 0, y: 0, width: 1280, height: 688 }]) {
    const w = fitWindow(area)
    expect(w.width, `width in ${area.width}x${area.height}`).toBeLessThanOrEqual(area.width)
    expect(w.height, `height in ${area.width}x${area.height}`).toBeLessThanOrEqual(area.height)
    expect(w.x).toBeGreaterThanOrEqual(area.x)
    expect(w.y).toBeGreaterThanOrEqual(area.y)
    expect(w.y + w.height).toBeLessThanOrEqual(area.y + area.height)
  }
})
