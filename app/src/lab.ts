import { hexToBytes, protocolOf } from './layout'
import type { TraceEvent } from './types'

// Pure helpers for the lesson views (pictures, measures). A test can call every function here.

/** `name=value;name=value` from a measure.result event. */
export function parseDetail(detail: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const part of detail.split(';')) {
    const at = part.indexOf('=')
    if (at > 0) out[part.slice(0, at).trim()] = part.slice(at + 1).trim()
  }
  return out
}

export const PICTURE_BYTES = 64 * 64

export interface Picture { clear: number[]; locked: number[]; mode: string }

/** A picture message is a wire.sent whose plain bytes are 64 by 64. The locked picture is the first 4,096 bytes of its `cipher` field. */
export function pictureOf(e: TraceEvent | null): Picture | null {
  if (!e || e.type !== 'wire.sent' || e.plain.length !== PICTURE_BYTES * 2) return null
  const cipher = e.fields.find(f => f.name === 'cipher')
  if (!cipher) return null
  const wire = hexToBytes(e.wire)
  return { clear: hexToBytes(e.plain), locked: wire.slice(cipher.offset, cipher.offset + PICTURE_BYTES), mode: e.message }
}

export interface Avalanche { flipped: boolean[]; count: number }

/** Two 32-byte digests in `plain`. A cell is true where the same bit differs between them. */
export function avalancheOf(plainHex: string): Avalanche | null {
  const b = hexToBytes(plainHex)
  if (b.length !== 64) return null
  const flipped: boolean[] = []
  for (let i = 0; i < 32; i++) for (let bit = 7; bit >= 0; bit--) flipped.push(((b[i] ^ b[32 + i]) >> bit & 1) === 1)
  return { flipped, count: flipped.filter(Boolean).length }
}

export function percent(part: number, whole: number): number {
  return whole > 0 ? Math.round((part / whole) * 100) : 0
}

/** The picture sent under a message name, found among the shown events. A measure or an unlock event of the same message points at it. */
export function pictureByMessage(events: readonly TraceEvent[], message: string): Picture | null {
  for (const e of events) if (e.message === message) { const p = pictureOf(e); if (p) return p }
  return null
}

// ---- lesson 4: the certificate chain ----

export type Status = 'pending' | 'pass' | 'fail'

export interface ChainView {
  root: TraceEvent | null
  leaf: TraceEvent | null
  proof: TraceEvent | null
  checks: Record<string, Status>
  rootToLeaf: Status
  leafToProof: Status
}

/** The latest result of each named check up to `upTo`. A fail stays a fail. */
export function checkStatuses(events: readonly TraceEvent[], upTo: number): Record<string, Status> {
  const out: Record<string, Status> = {}
  for (const e of events) {
    if (e.seq > upTo) break
    if (e.check && out[e.check.name] !== 'fail') out[e.check.name] = e.check.result
  }
  return out
}

const both = (a: Status | undefined, b: Status | undefined): Status => (a === 'fail' || b === 'fail' ? 'fail' : a === 'pass' && b === 'pass' ? 'pass' : 'pending')

export function chainOf(events: readonly TraceEvent[], upTo: number): ChainView {
  const shown = events.filter(e => e.seq <= upTo)
  const checks = checkStatuses(shown, upTo)
  return {
    root: shown.find(e => e.type === 'ca.certificate.issued' && e.message === 'RootCertificate') ?? null,
    leaf: shown.find(e => e.type === 'ca.certificate.issued' && e.message === 'ServerCertificate') ?? null,
    proof: shown.find(e => e.type === 'tls.handshake.sent' && e.message === 'CertificateVerify') ?? null,
    checks,
    rootToLeaf: both(checks['chain to trust anchor'], checks['signature verify']),
    leafToProof: checks['CertificateVerify signature'] ?? 'pending',
  }
}

// ---- lessons 5 and 6: key ladders ----

export interface Rung { key: string; holder: string; name: string; state: 'held' | 'erased'; derivedFrom: string[]; seq: number; fingerprint: string }

const TLS_LADDER = /^(tls11\.[a-z0-9_.]+|ssh\.[a-zA-Z0-9_.]+|early_secret|handshake_secret|master_secret|[cs]_hs_traffic|[cs]_ap_traffic|exp_master|x25519_shared|mlkem_shared|hybrid_shared)$/

export const isLadderEvent = (e: TraceEvent): boolean =>
  e.type.startsWith('dukpt.key.') || (e.type === 'secret.derived' && e.secrets.some(s => TLS_LADDER.test(s.name)))

/** Rungs in the order the engine emitted them. An erase event marks the rung erased, or adds it as erased when it was never derived. */
export function ladderRungs(events: readonly TraceEvent[], upTo: number): Rung[] {
  const rungs = new Map<string, Rung>()
  for (const e of events) {
    if (e.seq > upTo) break
    if (e.type === 'dukpt.key.erased') {
      const key = `${e.actor}.${e.message}`
      const prior = rungs.get(key)
      rungs.set(key, { key, holder: e.actor, name: e.message, state: 'erased', derivedFrom: prior?.derivedFrom ?? [], seq: prior?.seq ?? e.seq, fingerprint: prior?.fingerprint ?? '' })
    } else if (isLadderEvent(e)) {
      for (const s of e.secrets) { const key = `${s.holder}.${s.name}`; if (!rungs.has(key)) rungs.set(key, { key, holder: s.holder, name: s.name, state: 'held', derivedFrom: s.derivedFrom, seq: e.seq, fingerprint: s.hex ? '' : s.fingerprint }) }
    }
  }
  return [...rungs.values()]
}

/** The reader's register count, from the latest `Reader registers` measure. */
export function registers(events: readonly TraceEvent[], upTo: number): { held: number; next: number } | null {
  let out: { held: number; next: number } | null = null
  for (const e of events) {
    if (e.seq > upTo) break
    if (e.type === 'measure.result' && e.message === 'Reader registers') { const d = parseDetail(e.detail); out = { held: Number(d.held ?? 0), next: Number(d.next ?? 0) } }
  }
  return out
}

// ---- the Eavesdropper view: what each tab may show ----

/** True when every certificate the engine issued also crossed the wire in the clear, as in TLS 1.1. In TLS 1.3 the certificate travels locked. */
export function certificatesArePublic(events: readonly TraceEvent[]): boolean {
  const certs = events.filter(e => e.type === 'ca.certificate.issued' && e.plain)
  const wire = events.map(e => e.wire).join('|').toLowerCase()
  return certs.length > 0 && certs.every(e => wire.includes(e.plain.toLowerCase()))
}

// A listener has every byte of wire.sent, readable where visibleToWire is true and opaque where it is false, plus sizes, order, timing and
// what can be computed from those alone. It has no keys, no fingerprints, no text under a lock, no check results, and no measure taken inside an endpoint.

/** True when a token's fields cross the wire where a listener can read them. */
export const tokensArePublic = (events: readonly TraceEvent[]): boolean =>
  events.some(e => e.wire && e.fields.some(f => /^(?:token|proof)(?:Header|Claims)$/.test(f.name) && f.visibleToWire))

/** Why this tab is closed to a listener, or null when it may show. A tab closes when it holds what only an endpoint knows. */
export function closedToListener(tab: string, events: readonly TraceEvent[]): string | null {
  switch (tab) {
    case 'chain': return certificatesArePublic(events) ? null : 'The certificates travel locked in this lesson, so a listener cannot read them.'
    case 'token': return tokensArePublic(events) ? null : 'The tokens travel locked in this lesson, so a listener cannot read them.'
    case 'ladder': return 'Each side makes these keys in its own memory. None of them crosses the wire.'
    case 'onion': return 'The wrappers open inside the gateway and the bank. A listener sees only the outer bytes.'
    case 'timing': return 'This lab runs on one machine, so nothing here crosses a wire. It also shows the lab\'s secret, which a listener never sees.'
    default: return null
  }
}

/** What this tab means in the Eavesdropper view, when it stays open. */
export function listenerLabel(tab: string, events: readonly TraceEvent[]): string | null {
  switch (tab) {
    case 'chain': return certificatesArePublic(events) ? 'Public: these certificates cross the wire in the clear, so a listener reads them too.' : null
    case 'token': return tokensArePublic(events) ? 'Public: these tokens cross the wire in the clear, so a listener can decode the claims.' : null
    default: return null
  }
}

/** True for a measure a listener could take from the wire: repeated blocks in ciphertext, and claims in a token that crosses in the clear. */
export const listenerCanMeasure = (e: TraceEvent, events: readonly TraceEvent[]): boolean => /(?:^|;)repeats=/.test(e.detail) || ((e.message === 'token claims' || e.message === 'proof claims') && tokensArePublic(events))

// ---- lesson 7: the race ----

export interface RaceStats { messages: number; bytes: number; roundTrips: number | null }

/** Messages and bytes are counts of wire.sent events of one protocol. A round trip is a pair of direction changes before the client first sends application data. */
export function raceStats(events: readonly TraceEvent[], upTo: number, protocol: string): RaceStats {
  const sent = events.filter(e => e.seq <= upTo && e.type === 'wire.sent' && protocolOf(e) === protocol)
  let changes = 0
  let last = ''
  let reached = false
  for (const e of sent) {
    if (last && e.from !== last) changes++
    last = e.from
    if (e.from === 'client' && e.message === 'ApplicationData') { reached = true; break }
  }
  return { messages: sent.length, bytes: sent.reduce((n, e) => n + (e.wire.length >> 1), 0), roundTrips: reached ? Math.floor(changes / 2) : null }
}

export const protocols = (events: readonly TraceEvent[]): Set<string> => new Set(events.map(protocolOf).filter(Boolean))

// ---- lesson 8: host keys ----

export interface HostKeySeen { fingerprint: string; protocol: string; status: Status }

export function hostKeys(events: readonly TraceEvent[], upTo: number): HostKeySeen[] {
  const out: HostKeySeen[] = []
  for (const e of events) {
    if (e.seq > upTo) break
    if (e.type === 'ssh.hostkey.seen') out.push({ fingerprint: e.message, protocol: protocolOf(e), status: 'pending' })
    if (e.check?.name === 'known_hosts match') {
      // A refused key may fail the check before any card was shown. The card then says so, with an empty fingerprint.
      if (!out.length || out[out.length - 1].status !== 'pending') out.push({ fingerprint: '', protocol: protocolOf(e), status: e.check.result })
      else out[out.length - 1].status = e.check.result
    }
  }
  return out
}

// ---- lessons 10 and 11: tokens and timing ----

/** UTF-8 text of an event's hex bytes. Timing and claims events carry JSON text in `plain`. */
export function textOfHex(hex: string): string {
  try { return new TextDecoder().decode(Uint8Array.from(hexToBytes(hex))) } catch { return '' }
}

export function jsonOfEvent<T = Record<string, unknown>>(e: TraceEvent | null): T | null {
  if (!e || !e.plain) return null
  try { return JSON.parse(textOfHex(e.plain)) as T } catch { return null }
}

/** base64url text to a string. Returns null when the text is not valid base64url. */
export function b64urlText(s: string): string | null {
  try {
    const std = s.replace(/-/g, '+').replace(/_/g, '/')
    const bin = atob(std + '='.repeat((4 - (std.length % 4)) % 4))
    return new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0)))
  } catch { return null }
}

export interface TokenPart { name: 'header' | 'claims' | 'signature'; text: string; decoded: string | null }
export interface TokenView { kind: 'token' | 'proof'; parts: TokenPart[] }

/** The three parts of a compact token (or a DPoP proof) as the fields name them. Offsets index `wire`. */
export function tokenParts(e: TraceEvent | null, kind: 'token' | 'proof'): TokenView | null {
  if (!e || !e.wire) return null
  const parts: TokenPart[] = []
  for (const [name, field] of [['header', `${kind}Header`], ['claims', `${kind}Claims`], ['signature', `${kind}Signature`]] as const) {
    const f = e.fields.find(x => x.name === field)
    if (!f) continue
    const text = new TextDecoder().decode(Uint8Array.from(hexToBytes(e.wire.slice(f.offset * 2, (f.offset + f.length) * 2))))
    parts.push({ name, text, decoded: name === 'signature' ? null : b64urlText(text) })
  }
  return parts.length ? { kind, parts } : null
}

export const CLAIM_WORDS: Record<string, string> = {
  iss: 'who issued it', aud: 'who it is for', sub: 'who it is about', roles: 'roles', cap: 'extra permissions', iat: 'issued at', exp: 'expires', jti: 'one-time id',
  cnf: 'bound to this key', htm: 'the HTTP method', htu: 'the address', ath: 'hash of the token',
}

export const isTimeClaim = (k: string): boolean => k === 'iat' || k === 'exp'

export interface Hist { ns: number; count: number }
export interface TimingCase { compare: string; bufferSize: number; diffPosition: number; samples: number; meanNs: number; medianNs: number; p99Ns: number; histogram: Hist[]; aboveP99: number }
export interface TimingVerdict { leakyT: number | null; constantTimeT: number | null; controlT: number | null; managedT: number | null; minT: number; factor: number; constantTimeOverMinT: boolean; separated: boolean }
export interface TimingGuess { compare: string; correctBytes: number; totalBytes: number; blockBytes: number; samplesPerGuess: number; bytes: { value: number; marginNs: number }[] }

export interface TimingView {
  machine: { clr: string; pointerBytes: number } | null
  cases: { e: TraceEvent; c: TimingCase }[]
  managed: { e: TraceEvent; c: TimingCase }[]
  verdict: { e: TraceEvent; v: TimingVerdict } | null
  guesses: { e: TraceEvent; g: TimingGuess }[]
  failed: TraceEvent | null
}

export function timingOf(events: readonly TraceEvent[], upTo: number): TimingView {
  const view: TimingView = { machine: null, cases: [], managed: [], verdict: null, guesses: [], failed: null }
  for (const e of events) {
    if (e.seq > upTo) break
    if (e.type === 'timing.lab.started') view.machine = jsonOfEvent(e)
    else if (e.type === 'timing.samples') { const c = jsonOfEvent<TimingCase>(e); if (c) view.cases.push({ e, c }) }
    else if (e.type === 'timing.managed') { const c = jsonOfEvent<TimingCase>(e); if (c) view.managed.push({ e, c }) }
    else if (e.type === 'timing.verdict') { const v = jsonOfEvent<TimingVerdict>(e); if (v) view.verdict = { e, v } }
    else if (e.type === 'timing.guess.finished') { const g = jsonOfEvent<TimingGuess>(e); if (g) view.guesses.push({ e, g }) }
    else if (e.type === 'timing.failed') view.failed = e
  }
  return view
}

// ---- lesson 9: the onion ----

export interface OnionLayer { n: 1 | 2 | 3; name: string; state: 'absent' | 'closed' | 'open' | 'broken' }
export interface Onion { layers: OnionLayer[]; gatewayNote: string }

/** Three wrappers around one PIN. Each layer binds to one event (docs/lesson-9-names.md section 3). A layer reads `open` when the party that removes it has acted. */
export function onionOf(events: readonly TraceEvent[], upTo: number): Onion {
  const seen = events.filter(e => e.seq <= upTo)
  const has = (f: (e: TraceEvent) => boolean) => seen.some(f)
  const locked = has(e => e.type === 'pin.block.locked')
  const ssh = has(e => e.type === 'wire.sent' && e.hop === 'hop1' && e.message === 'ChannelData')
  const tls = has(e => e.type === 'wire.sent' && e.hop === 'hop2' && e.message === 'ApplicationData')
  const relayed = seen.find(e => e.type === 'gateway.envelope.relayed')
  const bankActed = has(e => e.actor === 'bank')
  const pinCheck = seen.find(e => e.check?.name === 'PIN block MAC at bank')
  const pinState = !locked ? 'absent' : pinCheck?.check?.result === 'fail' ? 'broken' : pinCheck?.check?.result === 'pass' ? 'open' : 'closed'
  return {
    layers: [
      { n: 1, name: 'PIN block, locked by DUKPT', state: pinState },
      { n: 2, name: 'inside SSH (hop 1)', state: !ssh ? 'absent' : relayed ? 'open' : 'closed' },
      { n: 3, name: 'inside TLS 1.3 (hop 2)', state: !tls ? 'absent' : bankActed ? 'open' : 'closed' },
    ],
    gatewayNote: relayed?.detail ?? '',
  }
}

/**
 * The holders that What each side knows shows, in column order. The columns follow the diagram's lanes, so Client stays left of Server.
 * The order of the key events can change between runs of one seed, so it must not decide the columns. A holder that is not a lane follows, in the order it first appears.
 */
export const holderColumns = (seen: readonly string[], lanes: readonly string[]): string[] => {
  const unique = [...new Set(seen)]
  return [...lanes.filter(l => unique.includes(l)), ...unique.filter(h => !lanes.includes(h))]
}
