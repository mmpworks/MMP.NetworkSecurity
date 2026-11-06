import { computed, reactive, watch } from 'vue'
import { addr, lessons, onShowKeys, replaceOpenSessions, startSession, ui } from './store'
import { hostGet, hostSend } from './host'
import copy from './wizard-copy.json'

// The Security setup state. The Host owns every rule (modes, states, the wizard moves). This module holds view state and sends the learner's answers.
// A reply from the Host replaces the copy held here, and nothing is merged (gem server-replaces-never-merges).

export type KeyMode = 'BuiltIn' | 'Mine'
export interface TypeRow { typeId: string; mode: KeyMode; state: string; version: number; judge: string; says: string; cause: string; usedBy: number[] }
export interface FlowRow { flowId: string; openRunId: string; stepIndex: number; stepCount: number }
export interface Msg { code: string; message: string }
export interface Step {
  runId: string; flowId: string; state: string; stepSeq: number; stepIndex: number; stepCount: number; kind: string; copyId: string
  facts: Record<string, any>[]; fields: Record<string, any>[]; choices: Record<string, any>[]; allowed: string[]; errors: Msg[]; warnings: Msg[]
}
export interface Problem { typeId: string; code: string; detail: string }

/** The five flows in screen order, with the plain button words and the type ids each one makes (wizards-ux.md 1.4). */
export const FLOWS = [
  { flowId: 'my-certificates', types: ['pki.root-ca', 'tls.trust', 'tls13.server', 'tls13.client', 'tls11.server'], lessons: [4, 5, 7, 9, 10] },
  { flowId: 'my-ssh', types: ['ssh.host-ed25519', 'ssh.host-rsa', 'ssh.client', 'ssh.known-hosts'], lessons: [8, 9] },
  { flowId: 'my-payment', types: ['dukpt.bdk', 'dukpt.pad'], lessons: [6, 9] },
  { flowId: 'my-login', types: ['token.issuer', 'device.enrolment'], lessons: [10] },
  { flowId: 'my-lesson-keys', types: ['lab.aes-key', 'lab.seal-key'], lessons: [1, 2] },
] as const

/** The six map groups, top to bottom (wizards-ux.md 1.2). */
export const GROUPS = [
  { title: 'Web security (TLS)', types: ['pki.root-ca', 'tls13.server', 'tls.trust', 'tls13.client', 'tls11.server'] },
  { title: 'Remote login (SSH)', types: ['ssh.host-ed25519', 'ssh.host-rsa', 'ssh.known-hosts', 'ssh.client'] },
  { title: 'Card PIN keys (DUKPT)', types: ['dukpt.bdk', 'dukpt.pad'] },
  { title: 'Sign-in tokens', types: ['token.issuer', 'device.enrolment'] },
  { title: 'Locks and seals', types: ['lab.aes-key', 'lab.seal-key'] },
] as const

export const REFUSAL_CODES = new Set(['SECURITY_TYPE_NOT_READY', 'SECURITY_TYPE_NOT_PROVEN', 'SECURITY_TYPES_DISAGREE'])

const COPY = copy as Record<string, string>
export const words = (id: string, fallback = ''): string => COPY[id] ?? fallback

export const sec = reactive({
  open: false,
  types: [] as TypeRow[],
  flows: [] as FlowRow[],
  showKeys: true,
  loaded: false,
  run: null as Step | null,
  busy: false,
  keepSheet: false,
  needs: null as { lesson: number; problems: Problem[] } | null,
  returnLesson: null as number | null,
  confirmBuiltin: false,
  fault: null as Msg | null,
})

const str = (v: unknown): string => (typeof v === 'string' ? v : v == null ? '' : String(v))
const list = (v: unknown): any[] => (Array.isArray(v) ? v : [])

export const flowOf = (typeId: string): string => FLOWS.find(f => (f.types as readonly string[]).includes(typeId))?.flowId ?? ''

function toType(t: any): TypeRow {
  const typeId = str(t.typeId)
  const fallback = FLOWS.find(f => (f.types as readonly string[]).includes(typeId))?.lessons ?? []
  const used = list(t.usedBy ?? t.lessons).map(Number).filter(Number.isFinite)
  return {
    typeId, mode: t.mode === 'Mine' ? 'Mine' : 'BuiltIn', state: str(t.state), version: Number(t.version ?? 0),
    judge: str(t.judge), says: str(t.says), cause: str(t.cause ?? t.detail), usedBy: used.length ? used : [...fallback],
  }
}

const toMsg = (m: any): Msg => ({ code: str(m?.code), message: str(m?.message) })

export function toStep(b: any): Step {
  const s = b?.step ?? b ?? {}
  return {
    runId: str(s.runId), flowId: str(s.flowId), state: str(s.state), stepSeq: Number(s.stepSeq ?? 0), stepIndex: Number(s.stepIndex ?? 0), stepCount: Number(s.stepCount ?? 0),
    kind: str(s.kind), copyId: str(s.copyId), facts: list(s.facts), fields: list(s.fields), choices: list(s.choices), allowed: list(s.allowed).map(str),
    errors: list(s.errors).map(toMsg), warnings: list(s.warnings).map(toMsg),
  }
}

function fault(code: string, message: string) { sec.fault = { code, message } }

export async function loadSecurity() {
  try {
    const b = await hostGet(addr, '/api/security')
    sec.types = list(b.types).map(toType)
    sec.flows = list(b.flows).map((f): FlowRow => ({ flowId: str(f.flowId), openRunId: str(f.openRunId), stepIndex: Number(f.stepIndex ?? 0), stepCount: Number(f.stepCount ?? 0) }))
    sec.showKeys = b.showKeys !== false
    sec.loaded = true
    sec.fault = null
  } catch (e: any) { fault(e?.status === 404 ? 'PRODUCT_MISSING' : 'HOST_SECURITY_FAILED', 'The course could not read the security setup from the engine.') }
}

export const mineCount = computed(() => sec.types.filter(t => t.mode === 'Mine').length)
export const keysChip = computed(() => (mineCount.value === 0 ? 'Keys: built-in' : `Keys: ${mineCount.value} of mine`))
const notReady = (t: TypeRow) => t.mode === 'Mine' && t.state !== 'Verified'
export const badgeCount = computed(() => sec.types.filter(notReady).length)
export const typeRow = (id: string): TypeRow | undefined => sec.types.find(t => t.typeId === id)
export const flowRow = (flowId: string): FlowRow | undefined => sec.flows.find(f => f.flowId === flowId)

/** Lessons whose types are not ready, for the key badge on the rail. */
export function lessonNeeds(n: number): TypeRow[] {
  return sec.types.filter(t => notReady(t) && FLOWS.some(f => f.lessons.includes(n as never) && (f.types as readonly string[]).includes(t.typeId)))
}

export interface Chip { id: string; text: string; tone: 'info' | 'success' | 'warning' | 'error'; icon: string }
/** One chip per state: words and an icon, never color alone (wizards-ux.md 1.2). */
export function chipFor(t: TypeRow): Chip {
  const paused = flowRow(flowOf(t.typeId))
  if (t.mode === 'BuiltIn') return { id: 'builtin', text: words('wizard.chip.builtin'), tone: 'info', icon: 'mdi-key-outline' }
  if (paused?.openRunId && t.state !== 'Verified') {
    return { id: 'paused', text: paused.stepCount ? `Setup paused at step ${paused.stepIndex} of ${paused.stepCount}` : 'Setup paused', tone: 'warning', icon: 'mdi-pause-circle-outline' }
  }
  switch (t.state) {
    case 'Unconfigured': return { id: 'needs-setup', text: words('wizard.chip.needs-setup'), tone: 'warning', icon: 'mdi-alert-outline' }
    case 'Configured': return { id: 'not-checked', text: words('wizard.chip.not-checked'), tone: 'warning', icon: 'mdi-help-circle-outline' }
    case 'Broken': return { id: 'broken', text: t.cause ? `${words('wizard.chip.broken')}: ${t.cause}` : words('wizard.chip.broken'), tone: 'error', icon: 'mdi-close-octagon-outline' }
    case 'Verified':
      if (noJudge(t)) return { id: 'no-outside-check', text: words('wizard.chip.no-outside-check'), tone: 'warning', icon: 'mdi-shield-alert-outline' }
      return { id: 'checked', text: words(`wizard.says.${t.says}`, `${words('wizard.chip.checked')} by ${t.judge || 'an outside tool'}`), tone: 'success', icon: 'mdi-check-circle-outline' }
    default: return { id: 'needs-setup', text: words('wizard.chip.needs-setup'), tone: 'warning', icon: 'mdi-alert-outline' }
  }
}

const noJudge = (t: TypeRow) => t.judge === 'none' || t.says === 'no-outside-judge'

export function actionFor(t: TypeRow): string {
  const c = chipFor(t).id
  return ({ builtin: 'Set up my own', 'needs-setup': 'Set up', 'not-checked': 'Check it', checked: 'Change', 'no-outside-check': 'Change', broken: 'Fix it', paused: 'Continue setup' } as Record<string, string>)[c] ?? 'Set up'
}

// ---- actions ----

export async function openSecurity() { sec.open = true; await loadSecurity() }
export function closeSecurity() { sec.open = false; sec.run = null; sec.returnLesson = null }

export async function setShowKeys(on: boolean) {
  const r = await hostSend(addr, 'PUT', '/api/security/show-keys', { on })
  if (r.status < 300) { sec.showKeys = on; await replaceOpenSessions(on) }
  else fault(str(r.body?.code) || 'SHOW_KEYS_FAILED', str(r.body?.message))
}

export async function setMode(typeId: string, mode: KeyMode): Promise<boolean> {
  const r = await hostSend(addr, 'PUT', `/api/security/types/${encodeURIComponent(typeId)}/mode`, { mode })
  await loadSecurity()
  if (r.status >= 300) { fault(str(r.body?.code) || 'MODE_FAILED', str(r.body?.message)); return false }
  return true
}

export async function useBuiltinEverywhere() {
  for (const t of sec.types.filter(x => x.mode === 'Mine')) await setMode(t.typeId, 'BuiltIn')
  sec.confirmBuiltin = false
}

/** Opens a flow. A run left open on the Host is reopened and a new one starts otherwise. */
export async function openFlow(flowId: string, returnLesson: number | null = null) {
  sec.returnLesson = returnLesson
  sec.busy = true
  try {
    const open = flowRow(flowId)?.openRunId
    const r = open ? await hostGet(addr, `/api/security/runs/${encodeURIComponent(open)}`).then(body => ({ status: 200, body })) : await hostSend(addr, 'POST', `/api/security/flows/${encodeURIComponent(flowId)}/runs`)
    if (r.status >= 300) return fault(str(r.body?.code) || 'WIZARD_START_FAILED', str(r.body?.message))
    sec.run = toStep(r.body)
    sec.fault = null
  } catch (e: any) { fault('WIZARD_START_FAILED', str(e?.message)) } finally { sec.busy = false }
}

/** Sends one event the Host allowed. The new step replaces the old one. */
export async function sendEvent(event: string, data?: Record<string, unknown>) {
  const run = sec.run
  if (!run || sec.busy) return
  sec.busy = true
  try {
    const r = await hostSend(addr, 'POST', `/api/security/runs/${encodeURIComponent(run.runId)}/events`, { event, stepSeq: run.stepSeq, data: data ?? {} })
    if (r.status >= 300 && !r.body?.runId) {
      // A refused event leaves the step where it stands. The Host names the state and the event in the code.
      sec.run = { ...run, errors: [{ code: str(r.body?.code) || 'WIZARD_EVENT_FAILED', message: str(r.body?.message) }] }
    } else sec.run = toStep(r.body)
  } catch (e: any) { fault('WIZARD_EVENT_FAILED', str(e?.message)) } finally { sec.busy = false }
  await loadSecurity()
}

export async function closeSheet(keep: boolean) {
  const run = sec.run
  sec.keepSheet = false
  if (run && !keep) await sendEvent('cancel')
  sec.run = null
  await loadSecurity()
}

// ---- arriving from a lesson (the refusal banner) ----

export async function showNeeds(lesson: number | null) {
  if (lesson == null) return
  await loadSecurity()
  try {
    const b = await hostGet(addr, `/api/security/readiness?lesson=${lesson}`)
    const problems = list(b.problems).map((p): Problem => ({ typeId: str(p.typeId), code: str(p.code), detail: str(p.detail) }))
    sec.needs = b.mayRun === false || problems.length ? { lesson, problems } : null
  } catch { sec.needs = null }
}

export function dismissNeeds() { sec.needs = null }

export async function setUpNow(typeId: string) {
  const lesson = sec.needs?.lesson ?? null
  sec.needs = null
  sec.open = true
  await openFlow(flowOf(typeId), lesson)
}

export async function useBuiltinForLesson() {
  const n = sec.needs
  if (!n) return
  for (const p of n.problems) await setMode(p.typeId, 'BuiltIn')
  sec.needs = null
  startSession(ui.mode)
}

export function backToLesson() {
  const n = sec.returnLesson
  closeSecurity()
  if (n != null) { ui.lesson = n; startSession(ui.mode) }
}

// A refused lesson start arrives as an error frame. The banner replaces the generic error line.
watch(() => ui.error, e => {
  if (e && REFUSAL_CODES.has(e.code)) { ui.error = null; void showNeeds(ui.lesson) }
})

export const lessonsBuilt = computed(() => lessons.value.filter(l => l.built))

// The Host broadcasts security.show-keys when any client flips the switch. The store replaces each open session, and this keeps the switch in step.
onShowKeys(on => { sec.showKeys = on })
