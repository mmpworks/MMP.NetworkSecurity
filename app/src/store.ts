import { computed, reactive, ref } from 'vue'
import { hostGet, normalizeError, normalizeEvent, openSocket, resolveHostAddress, type HostSocket } from './host'
import { evaluateUnlock, findBound, parseHighlight, TOURS, type Unlock } from './tour'
import type { AppMode, HostError, LessonRow, TourStep, TraceEvent, Transport, ViewMode } from './types'

// One module-level store, like sim.ts in the pump simulator. The Host's event list replaces the UI copy and never merges into it
// (gem server-replaces-never-merges). The store keeps only view state of its own: selection, view, mode, tour cursor.

export const CE_LABEL = 'CF-compiled, run on the desktop CLR, never run on CE'
export const GLASS_NOTE = 'Built to show the parts. Do not copy.'
export const LESSON_NOTES: Record<number, string> = {
  6: 'A managed heap can keep copies of a key, so the reader here cannot promise the key is gone from memory.',
  11: 'Managed code has no constant-time guarantee. The native library is the only place this course claims one.',
}

const DEFAULT_TITLES = [
  'Secrets and locks', 'Tamper seals', 'Agreeing in public', 'Who are you', 'TLS 1.3 message by message', 'Key per sale',
  'The old world', 'SSH', 'The bridge', 'Client proof and permission', 'Unmanaged space',
]

export interface SessionRec {
  id: string
  parentId: string
  label: string
  lesson: number
  seed: number
  trainingOnly: boolean
  transportKind: string
  events: TraceEvent[]
  finished: { outcome: string; code: string; check: string } | null
  replay: boolean
}

export const addr = resolveHostAddress()
export const hostState = ref<'connecting' | 'connected' | 'offline'>('connecting')
const TOY_LESSON: LessonRow = { lesson: 0, title: 'Start here', built: true, lanes: ['client', 'server'], attacks: [{ attackId: 'L0-flip-wire-byte', label: 'Flip a byte on the wire', expectCheck: 'echo compare', expectCode: 'ECHO_MISMATCH' }] }
export const lessons = ref<LessonRow[]>([TOY_LESSON, ...DEFAULT_TITLES.map((title, i) => ({ lesson: i + 1, title, built: false, lanes: [], attacks: [] }))])
export const cePanel = ref<{ label: string; state: string } | null>(null)

export const ui = reactive({
  lesson: null as number | null,
  mode: 'tour' as AppMode,
  view: 'endpoints' as ViewMode,
  transport: 'glass' as Transport,
  speed: 1,
  theme: (safeGet('mmpns.theme') ?? 'system') as 'system' | 'dark' | 'light',
  sessions: [] as SessionRec[],
  activeId: '',
  viewUpTo: null as number | null,
  selectedSeq: null as number | null,
  selectedByte: null as number | null,
  showPlain: null as boolean | null,
  error: null as HostError | null,
  engine: 'idle' as 'idle' | 'running' | 'stepping' | 'waiting' | 'finished',
  shortcuts: false,
  follow: true,
  inspectorTab: 'bytes' as 'bytes' | 'picture' | 'measures' | 'chain' | 'ladder' | 'hostkey',
})

export const tour = reactive({
  active: false,
  sessionId: '',
  stepIndex: 0,
  bound: [] as number[],
  driving: false,
  unreachable: '' as string,
  actionDone: false,
  tryItStart: 0,
  seen: new Set<string>(),
})

function safeGet(k: string): string | null { try { return localStorage.getItem(k) } catch { return null } }
function safeSet(k: string, v: string) { try { localStorage.setItem(k, v) } catch { /* storage may be blocked */ } }

let sock: HostSocket | null = null
let waiter: (() => void) | null = null
let reqCounter = 0
let everOpen = false

export const active = computed(() => ui.sessions.find(s => s.id === ui.activeId) ?? null)
export const allEvents = computed(() => active.value?.events ?? [])
export const shownEvents = computed(() => (ui.viewUpTo == null ? allEvents.value : allEvents.value.slice(0, ui.viewUpTo + 1)))
export const selectedEvent = computed<TraceEvent | null>(() => {
  const list = shownEvents.value
  if (ui.selectedSeq != null) return list.find(e => e.seq === ui.selectedSeq) ?? null
  for (let i = list.length - 1; i >= 0; i--) if (list[i].wire || list[i].plain) return list[i]
  return list.length ? list[list.length - 1] : null
})
export const lessonRow = computed(() => lessons.value.find(l => l.lesson === ui.lesson) ?? null)
export const steps = computed<TourStep[]>(() => (ui.lesson != null ? TOURS.get(ui.lesson) ?? [] : []))
export const step = computed<TourStep | null>(() => steps.value[tour.stepIndex] ?? null)
export const isReal = computed(() => (active.value ? active.value.transportKind === 'real' : ui.transport === 'real'))
export const trainingChip = computed(() => (isReal.value ? 'OS TRANSPORT' : 'TRAINING ONLY'))

export const unlock = computed<Unlock>(() => {
  const s = step.value
  if (!s) return { open: false, reason: '' }
  if (tour.unreachable) return { open: false, reason: tour.unreachable }
  const events = allEvents.value
  const sinceTryIt = active.value?.id === tour.sessionId ? events.slice(tour.tryItStart) : events
  return evaluateUnlock(s, {
    boundIndex: tour.bound[tour.stepIndex] ?? -1, events, view: ui.view, selectedSeq: ui.selectedSeq, actionDone: tour.actionDone, outcome: active.value?.parentId ? active.value.finished?.outcome ?? '' : '', caughtCheck: active.value?.parentId && active.value.finished?.outcome === 'caught' ? active.value.finished.check : '', eventsSinceTryIt: sinceTryIt,
  })
})

function nextReq(): string { const id = `r${++reqCounter}`; myRequests.add(id); return id }
function fail(code: string, message: string, retryable = false) { ui.error = { code, message, retryable, requestId: '' } }
export function clearError() { ui.error = null }

// ---- connection ----

export function connect() {
  if (sock) return
  applyTheme()
  sock = openSocket(addr, {
    onOpen: () => { hostState.value = 'connected'; ui.error = null; void refreshHostData(); if (everOpen) void resync(); everOpen = true },
    onClose: () => { if (hostState.value === 'connected') hostState.value = 'offline'; else if (everOpen) hostState.value = 'offline' },
    onFrame,
  })
  // A first connect that never opens is an offline Host, not an endless "connecting".
  setTimeout(() => { if (hostState.value === 'connecting') hostState.value = 'offline' }, 8000)
}

export function retryConnect() { hostState.value = 'connecting'; sock?.close(); sock = null; everOpen = false; connect() }

async function refreshHostData() {
  try {
    const body = await hostGet(addr, '/api/lessons')
    const rows: any[] = Array.isArray(body) ? body : body?.lessons ?? []
    // Lesson 0 is the toy. The rail always shows it as "Start here" and never asks the Host's list (the list holds lessons 1 to 11).
    lessons.value = [0, ...DEFAULT_TITLES.map((_, i) => i + 1)].map(n => {
      const r = n === 0 ? undefined : rows.find(x => x.lesson === n)
      if (n === 0) return TOY_LESSON
      return {
        lesson: n, title: r?.title || DEFAULT_TITLES[n - 1], built: !!r?.built, lanes: Array.isArray(r?.lanes) ? r.lanes.map(String) : [],
        attacks: Array.isArray(r?.attacks) ? r.attacks.map((a: any) => (typeof a === 'string' ? { attackId: a, label: a } : { attackId: String(a.attackId ?? a.id), label: String(a.label ?? a.attackId ?? a.id), expectCheck: a.expectCheck, expectCode: a.expectCode })) : [],
      }
    })
  } catch (e: any) { fail('HOST_LESSONS_FAILED', String(e?.message ?? e), true) }
  try { const ce = await hostGet(addr, '/api/ce'); cePanel.value = { label: String(ce?.label ?? CE_LABEL), state: String(ce?.state ?? '') } } catch { cePanel.value = null }
}

async function resync() {
  const s = active.value
  if (!s || s.replay) return
  try {
    const last = s.events.length ? s.events[s.events.length - 1].seq : 0
    const body = await hostGet(addr, `/api/sessions/${s.id}/events?after=${last}`)
    const rows: any[] = Array.isArray(body) ? body : body?.events ?? []
    s.events = [...s.events, ...rows.map(normalizeEvent).filter(e => e.seq > last)]
  } catch { /* the live feed keeps going */ }
}

// The Host sends every frame to every open socket. This client owns only the sessions it asked for: a session.started whose
// requestId it sent. A trace or finished frame can arrive ahead of its session.started, so frames of unknown sessions wait by id.
const myRequests = new Set<string>()
const mySessions = new Set<string>()
const pending = new Map<string, any[]>()

function hold(f: any) {
  const id = String(f.sessionId)
  const list = pending.get(id) ?? []
  if (list.length < 2000) list.push(f)
  pending.set(id, list)
  if (pending.size > 20) pending.delete(pending.keys().next().value as string)
}

function onFrame(f: any) {
  switch (f?.type) {
    case 'session.started':
      if (!myRequests.has(String(f.requestId))) return
      mySessions.add(String(f.sessionId))
      onStarted(f)
      for (const p of pending.get(String(f.sessionId)) ?? []) onFrame(p)
      pending.delete(String(f.sessionId))
      return
    case 'trace': case 'session.finished':
      if (!mySessions.has(String(f.sessionId))) return hold(f)
      return f.type === 'trace' ? onTrace(f) : onFinished(f)
    case 'session.forked': return mySessions.has(String(f.sessionId)) || mySessions.has(String(f.parentId)) ? onForked(f) : undefined
    case 'error':
      if (f.requestId && !myRequests.has(String(f.requestId))) return
      ui.error = normalizeError(f)
      return wake()
  }
}

function onStarted(f: any) {
  const lesson = ui.lesson ?? 0
  const rec: SessionRec = {
    id: String(f.sessionId), parentId: '', label: `lesson ${lesson}`, lesson, seed: Number(f.seed ?? 0),
    trainingOnly: !!f.trainingOnly, transportKind: String(f.transportKind ?? (f.trainingOnly ? 'glass' : 'real')), events: [], finished: null, replay: false,
  }
  ui.sessions = [...ui.sessions.filter(s => s.id !== rec.id), rec]
  ui.activeId = rec.id
  ui.viewUpTo = null
  ui.selectedSeq = null
  ui.engine = 'stepping'
  if (tour.active && !tour.sessionId) tour.sessionId = rec.id
  wake()
}

function onTrace(f: any) {
  const ev = normalizeEvent(f)
  const s = ui.sessions.find(x => x.id === ev.sessionId)
  if (!s) return
  if (!s.events.some(e => e.seq === ev.seq)) s.events = [...s.events, ev]
  if (ev.waiting) ui.engine = 'waiting'
  wake()
}

function onForked(f: any) {
  // The fork's session.started comes first and already made the record. This frame names its parent and its attack.
  const parent = ui.sessions.find(s => s.id === String(f.parentId))
  const rec = ui.sessions.find(s => s.id === String(f.sessionId))
  if (!rec) return
  rec.parentId = String(f.parentId)
  rec.label = `attack: ${f.attackId ?? 'tamper'}`
  if (parent) { rec.lesson = parent.lesson; rec.seed = parent.seed }
  // session.started already made the fork active. This frame can arrive after the learner pressed Next, so it never changes the active session.
  // An attack fork runs to its result, so the failing check shows without a second click.
  sock?.send({ type: 'session.run', sessionId: rec.id })
  wake()
}

function onFinished(f: any) {
  const s = ui.sessions.find(x => x.id === String(f.sessionId))
  if (s) s.finished = { outcome: String(f.outcome ?? ''), code: String(f.code ?? ''), check: String(f.check ?? '') }
  if (String(f.sessionId) === ui.activeId) ui.engine = 'finished'
  wake()
}

function wake() { const w = waiter; waiter = null; w?.() }
function nextActivity(ms: number): Promise<boolean> {
  return new Promise(resolve => {
    const t = setTimeout(() => { waiter = null; resolve(false) }, ms)
    waiter = () => { clearTimeout(t); resolve(true) }
  })
}

// ---- lessons and sessions ----

export function selectLesson(n: number) {
  if (ui.lesson === n) return
  ui.lesson = n
  tour.active = false
  tour.sessionId = ''
  tour.stepIndex = 0
  tour.bound = []
  tour.unreachable = ''
  ui.activeId = ''
  ui.viewUpTo = null
  ui.selectedSeq = null
  ui.engine = 'idle'
  ui.error = null
}

export function startSession(mode: AppMode) {
  const n = ui.lesson
  if (n == null || !lessonRow.value?.built) return
  ui.mode = mode
  ui.error = null
  tour.active = mode === 'tour'
  tour.sessionId = ''
  tour.stepIndex = 0
  tour.bound = []
  tour.unreachable = ''
  tour.actionDone = false
  tour.tryItStart = 0
  ui.activeId = ''
  ui.viewUpTo = null
  ui.selectedSeq = null
  sock?.send({ type: 'session.start', requestId: nextReq(), lesson: n, seed: 20261105, mode: 'step', transport: ui.transport })
  if (mode === 'tour') void enterStep(0)
}

export function stepEngine() { sock?.send({ type: 'session.step', sessionId: ui.activeId }); ui.engine = 'stepping' }
export function runEngine() { sock?.send({ type: 'session.run', sessionId: ui.activeId }); ui.engine = 'running' }
export function pauseEngine() { sock?.send({ type: 'session.pause', sessionId: ui.activeId }); ui.engine = 'stepping' }
export function restartSession() { if (ui.lesson != null) startSession(ui.mode) }
export function saveSession() { if (ui.activeId) sock?.send({ type: 'session.save', sessionId: ui.activeId }) }
export function loadTrace(file: string) { if (file) sock?.send({ type: 'session.load', file }) }

// ---- tour driver ----

async function waitForSession(): Promise<boolean> {
  const have = () => ui.sessions.some(x => x.id === tour.sessionId)
  for (let i = 0; i < 40 && !have(); i++) { if (!(await nextActivity(500))) continue }
  return have()
}

/** Moves the engine, one event at a time, until the bound event of step i is in the list. The engine then waits for the learner. */
async function enterStep(i: number) {
  const s = steps.value[i]
  tour.stepIndex = i
  tour.actionDone = false
  tour.unreachable = ''
  tour.tryItStart = allEvents.value.length
  if (!s) return
  if (tour.bound[i] != null) { if (tour.bound[i] >= 0) ui.viewUpTo = tour.bound[i]; return }
  if (s.bind.kind === 'concept') { tour.bound[i] = -1; return }
  tour.driving = true
  try {
    if (!(await waitForSession())) { tour.unreachable = 'The engine did not start a session'; return }
    // The tour reads its own session, never the active one: an attack fork can be active while the learner moves on.
    const ts = () => ui.sessions.find(x => x.id === tour.sessionId)
    const prev = Math.max(0, ...tour.bound.slice(0, i))
    for (let guard = 0; guard < 500; guard++) {
      // The first match at or after the previous step. A tour may teach in an order the engine did not emit, so a match before it also counts.
      const events = ts()?.events ?? []
      let idx = findBound(s, events, prev)
      if (idx < 0) idx = findBound(s, events, 0)
      if (idx >= 0) { tour.bound[i] = idx; ui.viewUpTo = s.pause === 'none' ? null : idx; ui.selectedSeq = null; markSeen(s); return }
      if (ts()?.finished) { tour.unreachable = 'The session ended before the engine sent this message'; return }
      // A step command can be lost while an engine starts up (lesson 8 showed it). Send it again every 3 seconds, and give up after 15.
      let answered = false
      for (let attempt = 0; attempt < 5 && !answered; attempt++) {
        sock?.send({ type: 'session.step', sessionId: tour.sessionId })
        ui.engine = 'stepping'
        answered = await nextActivity(3000)
      }
      if (!answered) { fail('STEP_TIMEOUT', 'The engine sent nothing for 15 seconds.', true); tour.unreachable = 'The engine is not answering'; return }
      if (ui.error) { tour.unreachable = 'The engine reported an error'; return }
    }
  } finally { tour.driving = false }
}

function markSeen(s: TourStep) {
  tour.seen.add(s.id)
  const last = steps.value[steps.value.length - 1]
  if (last && tour.seen.has(last.id)) safeSet(`mmpns.done.${ui.lesson}`, '1')
}

export function lessonDone(n: number): boolean { return safeGet(`mmpns.done.${n}`) === '1' }

function backToTourSession() { if (tour.sessionId && ui.activeId !== tour.sessionId) { ui.activeId = tour.sessionId; ui.viewUpTo = null } }

export async function tourNext() {
  if (!unlock.value.open) return
  backToTourSession()
  if (tour.stepIndex < steps.value.length - 1) await enterStep(tour.stepIndex + 1)
}

export function tourBack() {
  if (tour.stepIndex <= 0) return
  backToTourSession()
  const i = tour.stepIndex - 1
  tour.stepIndex = i
  tour.actionDone = false
  tour.unreachable = ''
  const b = tour.bound[i]
  if (b != null && b >= 0) ui.viewUpTo = b
  else { const prior = Math.max(-1, ...tour.bound.slice(0, i)); ui.viewUpTo = prior >= 0 ? prior : null }
  ui.selectedSeq = null
}

/** Replays the step's animation from stored events. No engine command goes out. */
export const replayTick = ref(0)
export function tourReplay() { replayTick.value++ }

export function doTryIt() {
  const s = step.value
  const t = s?.tryIt
  if (!s || !t) return
  const a = t.action
  const bound = allEvents.value[tour.bound[tour.stepIndex] ?? -1] ?? selectedEvent.value
  tour.tryItStart = allEvents.value.length
  switch (a.type) {
    case 'set-view': ui.view = (a.value as ViewMode) ?? 'eavesdropper'; break
    case 'select-event': if (bound) ui.selectedSeq = bound.seq; break
    case 'press-run': runEngine(); break
    case 'run-attack': if (a.attackId) attack({ attackId: a.attackId }); break
    case 'flip-byte': if (bound) attack({ atSeq: bound.seq, kind: 'flip-byte', offset: ui.selectedByte ?? Math.max(0, Math.floor(bound.wire.length / 4)), xor: 1 }); break
    case 'toggle-field': break
  }
  tour.actionDone = true
}

export function attack(p: { attackId?: string; atSeq?: number; kind?: string; offset?: number; xor?: number }) {
  if (!tour.sessionId && !ui.activeId) return
  sock?.send({ type: 'session.attack', requestId: nextReq(), sessionId: tour.active ? tour.sessionId || ui.activeId : ui.activeId, ...p })
}

export function flipSelectedByte() {
  const e = selectedEvent.value
  if (!e || ui.selectedByte == null) return
  attack({ atSeq: e.seq, kind: 'flip-byte', offset: ui.selectedByte, xor: 1 })
}

export function selectEvent(seq: number | null) { ui.selectedSeq = seq; ui.selectedByte = null }

export function switchSession(id: string) { ui.activeId = id; ui.viewUpTo = null; ui.selectedSeq = null }

export function setMode(m: AppMode) {
  ui.mode = m
  if (m === 'free') { tour.active = false; ui.viewUpTo = null } else if (active.value) tour.active = true
}

export function setTheme(t: 'system' | 'dark' | 'light') { ui.theme = t; safeSet('mmpns.theme', t); applyTheme() }

export function applyTheme() {
  const dark = ui.theme === 'dark' || (ui.theme === 'system' && window.matchMedia?.('(prefers-color-scheme: dark)').matches)
  document.documentElement.dataset.theme = dark ? 'dark' : 'light'
  themeHook?.(dark ? 'nsDark' : 'nsLight')
}
let themeHook: ((name: string) => void) | null = null
export function onTheme(h: (name: string) => void) { themeHook = h; applyTheme() }

/** True when the current tour step highlights this target (ux-design.md section 3.1 grammar `<panel>:<kind>=<name>`). */
const highlights = computed(() => (tour.active ? step.value?.highlight ?? [] : []).map(parseHighlight).filter((h): h is NonNullable<typeof h> => h !== null))
export function isHighlighted(panel: string, kind: string, name: string): boolean {
  return highlights.value.some(h => h.panel === panel && h.kind === kind && h.name === name)
}

/** Panels show everything up to the selected event. With no explicit selection they show everything shown, so a check that comes after the last byte still appears. */
export const upToSeq = computed(() => (ui.selectedSeq != null ? selectedEvent.value?.seq ?? Infinity : Infinity))
