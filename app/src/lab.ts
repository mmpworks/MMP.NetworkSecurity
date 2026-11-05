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

export interface Rung { key: string; holder: string; name: string; state: 'held' | 'erased'; derivedFrom: string[]; seq: number }

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
      rungs.set(key, { key, holder: e.actor, name: e.message, state: 'erased', derivedFrom: prior?.derivedFrom ?? [], seq: prior?.seq ?? e.seq })
    } else if (isLadderEvent(e)) {
      for (const s of e.secrets) { const key = `${s.holder}.${s.name}`; if (!rungs.has(key)) rungs.set(key, { key, holder: s.holder, name: s.name, state: 'held', derivedFrom: s.derivedFrom, seq: e.seq }) }
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
