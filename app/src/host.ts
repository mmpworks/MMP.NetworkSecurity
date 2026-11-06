import type { HostError, TraceCheck, TraceEvent, TraceField, TraceSecret } from './types'

// The renderer learns the Host address and token from the Electron preload (window.netsec.host) or from ?port=&token= in the URL.
export interface HostAddress { port: number; token: string }

declare global {
  interface Window { netsec?: { host?: Partial<HostAddress> } }
}

export function resolveHostAddress(win: Window = window): HostAddress {
  const q = new URLSearchParams(win.location.search)
  const injected = win.netsec?.host
  const port = Number(q.get('port') ?? injected?.port ?? 5180)
  const token = q.get('token') ?? injected?.token ?? ''
  return { port, token }
}

const str = (v: unknown): string => (typeof v === 'string' ? v : v == null ? '' : String(v))
const arr = (v: unknown): any[] => (Array.isArray(v) ? v : [])

/** One place that maps the Host's JSON onto TraceEvent. Missing pieces become empty values, so a thin event never throws. */
export function normalizeEvent(frame: any): TraceEvent {
  const e = frame?.event ?? frame ?? {}
  const waiting = e.waiting && typeof e.waiting === 'object' ? str(e.waiting.actor) : str(e.waiting ?? e.waitingFor)
  const c = e.check
  const check: TraceCheck | null = c
    ? { id: str(c.id), name: str(c.name), result: c.result === 'fail' || c.passed === false ? 'fail' : 'pass', code: str(c.code), detail: str(c.detail) }
    : null
  return {
    seq: Number(frame?.seq ?? e.seq ?? 0),
    eventId: str(e.eventId),
    streamId: str(e.streamId),
    sessionId: str(frame?.sessionId ?? e.sessionId),
    traceId: str(e.traceId),
    hop: str(e.hop),
    actor: str(e.actor),
    from: str(e.from),
    to: str(e.to),
    type: str(e.type),
    message: str(e.message),
    step: str(e.step),
    wire: str(e.wire).toLowerCase(),
    plain: str(e.plain).toLowerCase(),
    fields: arr(e.fields).map((f): TraceField => ({
      name: str(f.name), offset: Number(f.offset ?? 0), length: Number(f.length ?? 0),
      kind: (f.kind ?? 'data') as TraceField['kind'], visibleToWire: f.visibleToWire !== false, gloss: str(f.gloss),
    })),
    secrets: arr(e.secrets).map((s): TraceSecret => ({ holder: str(s.holder), name: str(s.name), hex: str(s.hex).toLowerCase(), derivedFrom: arr(s.derivedFrom).map(str), fingerprint: str(s.fingerprint).toLowerCase(), length: Number(s.length ?? str(s.hex).length / 2), hidden: str(s.hidden) })),
    check,
    waiting,
    detail: str(e.detail),
    typeId: str(e.typeId),
    version: Number(e.version ?? 0),
    provider: str(e.provider),
  }
}

export function normalizeError(m: any): HostError {
  return { code: str(m?.code) || 'HOST_ERROR', message: str(m?.message) || 'The engine reported an error.', retryable: !!m?.retryable, requestId: str(m?.requestId) }
}

export async function hostGet(addr: HostAddress, path: string): Promise<any> {
  const r = await fetch(`http://127.0.0.1:${addr.port}${path}`, { headers: { Authorization: `Bearer ${addr.token}` } })
  if (!r.ok) throw Object.assign(new Error(`GET ${path} returned ${r.status}`), { status: r.status, body: await r.json().catch(() => null) })
  return r.json()
}

export interface HostReply { status: number; body: any }

/** POST or PUT with a JSON body. An error status still returns its body, so the caller reads the Host's error code. */
export async function hostSend(addr: HostAddress, method: 'POST' | 'PUT', path: string, payload?: unknown): Promise<HostReply> {
  const r = await fetch(`http://127.0.0.1:${addr.port}${path}`, {
    method,
    headers: { Authorization: `Bearer ${addr.token}`, 'Content-Type': 'application/json' },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  })
  const text = await r.text()
  let body: any = null
  try { body = text ? JSON.parse(text) : null } catch { body = { code: 'HOST_BAD_REPLY', message: text.slice(0, 200) } }
  return { status: r.status, body }
}

export interface HostSocket {
  send(frame: Record<string, unknown>): void
  close(): void
}

export interface SocketHandlers {
  onOpen(): void
  onClose(): void
  onFrame(frame: any): void
}

/** A WebSocket to /ws. It reconnects every 2 s until close() runs. The caller replays missed events from REST on reconnect. */
export function openSocket(addr: HostAddress, h: SocketHandlers): HostSocket {
  let ws: WebSocket | null = null
  let closed = false
  const connect = () => {
    ws = new WebSocket(`ws://127.0.0.1:${addr.port}/ws?token=${encodeURIComponent(addr.token)}`)
    ws.onopen = () => h.onOpen()
    ws.onmessage = ev => { try { h.onFrame(JSON.parse(String(ev.data))) } catch { /* a bad frame is dropped */ } }
    ws.onclose = () => { h.onClose(); if (!closed) setTimeout(connect, 2000) }
    ws.onerror = () => { /* onclose follows */ }
  }
  connect()
  return {
    send: frame => { if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(frame)) },
    close: () => { closed = true; ws?.close() },
  }
}
