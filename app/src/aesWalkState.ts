import { reactive, watch } from 'vue'
import gloss from './walk-gloss.json'
import { hostGet, hostSend } from './host'
import { loadSecurity, sec } from './security'
import { addr, hostState, onSocketClose, ui } from './store'
import type { AesBlockReply, AesTables, AesTypedCut } from './walk'

/** The key sizes the picker offers. The engine serves each one on the block route (design section 2.2b). */
export const KEY_SIZES = [128, 192, 256] as const
export type KeyBits = typeof KEY_SIZES[number]

/** Chapter 1's text when the box is empty (design 2.2g), and the lesson's long text the strip shows (sections-plan R1). Both are lesson 1's public text. */
export const DEFAULT_BLOCK_TEXT: string = gloss.typed.defaultBlock
export const LESSON_TEXT: string = gloss.typed.lessonText
/** Chapter 1 walks block 1 of the text, so the strip marks block index 0 current, and the link line starts there. */
export const CURRENT_STRIP_BLOCK = 0

// The AES block walk's state, and the flip-race rule of docs/walkthrough-design.md section 3.5:
// 1. A generation counter rises, and the run's walk clears, when Show keys goes off by any route and when the socket closes.
// 2. A run reply from an old generation, or one that lands while Show keys is off, is dropped.
// 3. After a reconnect the app reads the toggle first, and fetches the run's walk again only when it is on.
// 4. A walk reply lives only here: it never enters a session, /events, or a save.
// The practice walk (design 2.2g) runs on the public practice key and reads no run, so it stays open with Show keys off.
export const aesWalk = reactive({
  gen: 0,
  sessionId: '',
  lesson: null as number | null,
  block: null as AesBlockReply | null,
  /** How the typed text was cut into the block. Only a practice walk has one. */
  cut: null as AesTypedCut | null,
  keyBits: 128 as KeyBits,
  /** What the learner typed. Empty means the default text. */
  typed: '',
  /** The learner asked for the practice walk beside a run (the offer on the closed walk). */
  chosePractice: false,
  /** The walk panel has been on screen, so a reconnect has a walk to bring back. */
  opened: false,
  // The tables are public and hold no key byte, so they stay after a flip to OFF (design section 2.3).
  tables: null as AesTables | null,
  loading: false,
  error: '',
  closedBySocket: false,
})

/** The practice walk shows when there is no run, when the learner typed text, or when the learner asked for it. */
export const isPractice = () => !aesWalk.sessionId || aesWalk.typed !== '' || aesWalk.chosePractice

export function clearAesWalk() {
  aesWalk.gen++
  aesWalk.block = null
  aesWalk.cut = null
  aesWalk.loading = false
}

/** Fetches the walk the state calls for: the run's block, or the practice block. */
export function refreshAesWalk() {
  if (isPractice()) void fetchPracticeBlock()
  else if (aesWalk.sessionId) void fetchAesBlock(aesWalk.sessionId)
}

async function fetchAesBlock(sessionId: string) {
  const gen = begin()
  if (!sec.showKeys) return
  aesWalk.loading = true
  try {
    // Chapter 1 is block 1 of the run's text, at the key size the picker holds (design sections 2.2b and 3.4).
    // The walk needs the tables too: Nk comes from their size table. Each call names itself in a failure, so the error line says which part failed.
    const [body] = await Promise.all([
      named('the block route', hostGet(addr, `/api/sessions/${encodeURIComponent(sessionId)}/walk/aes/block?source=text&keyBits=${aesWalk.keyBits}`)),
      named('the tables route', loadAesTables()),
    ])
    if (gen !== aesWalk.gen || !sec.showKeys || isPractice()) return
    aesWalk.block = body as AesBlockReply
  } catch (e: any) {
    if (gen === aesWalk.gen) aesWalk.error = e instanceof RouteFailure ? e.message : describe(e)
  } finally {
    if (gen === aesWalk.gen) aesWalk.loading = false
  }
}

/** The learner's text, or the default, under the public practice key (design 2.2g). The engine cuts the 16 bytes, so the rule lives in one place. */
async function fetchPracticeBlock() {
  const gen = begin()
  aesWalk.loading = true
  try {
    const [reply] = await Promise.all([
      named('the typed-block route', postJson('/api/walk/aes/typed-block', { text: aesWalk.typed || DEFAULT_BLOCK_TEXT, keyBits: aesWalk.keyBits })),
      named('the tables route', loadAesTables()),
    ])
    if (gen !== aesWalk.gen || !isPractice()) return
    aesWalk.block = reply.walk as AesBlockReply
    aesWalk.cut = reply.cut as AesTypedCut
  } catch (e: any) {
    if (gen === aesWalk.gen) aesWalk.error = e instanceof RouteFailure ? e.message : describe(e)
  } finally {
    if (gen === aesWalk.gen) aesWalk.loading = false
  }
}

/** Starts a fetch: a new generation, and an empty walk until the reply lands. */
function begin(): number {
  const gen = ++aesWalk.gen
  aesWalk.block = null
  aesWalk.cut = null
  aesWalk.error = ''
  aesWalk.closedBySocket = false
  return gen
}

/** A POST that throws on an error status, with the Host's body attached, as hostGet does. */
export async function postJson(path: string, payload: unknown): Promise<any> {
  const r = await hostSend(addr, 'POST', path, payload)
  if (r.status >= 400) throw Object.assign(new Error(`POST ${path} returned ${r.status}`), { status: r.status, body: r.body })
  return r.body
}

export const describe = (e: any): string => String(e?.body?.message ?? e?.body?.code ?? (e?.status ? `HTTP_${e.status}` : 'WALK_FAILED'))

/** A failed call, named by the route it came from, such as "the tables route failed: HTTP_500". */
class RouteFailure extends Error {}
const named = <T>(route: string, p: Promise<T>): Promise<T> => p.catch(e => { throw new RouteFailure(`${route} failed: ${describe(e)}`) })

// One shared request: two callers that race before the first reply wait on the same promise. A failure clears it, so the next call tries again.
let tablesRequest: Promise<AesTables> | null = null

/** The public tables, fetched once. The route stays open with Show keys off, so the closed walk can still show the S-box (design section 2.3). */
export function loadAesTables(): Promise<AesTables> {
  if (aesWalk.tables) return Promise.resolve(aesWalk.tables)
  tablesRequest ??= (hostGet(addr, '/api/walk/aes/tables') as Promise<AesTables>)
    .then(t => { aesWalk.tables = t; return t })
    .finally(() => { tablesRequest = null })
  return tablesRequest
}

/** The key size picker: the walk fetches its block again at the new size. */
export function pickKeyBits(bits: KeyBits) {
  if (bits === aesWalk.keyBits && aesWalk.block) return
  aesWalk.keyBits = bits
  refreshAesWalk()
}

/** The text box: a new text fetches the practice block. Clearing it goes back to the run's block, when there is a run (design 2.2g). */
export function setTypedText(text: string) {
  if (text === aesWalk.typed) return
  aesWalk.typed = text
  refreshAesWalk()
}

/** The offer on the closed walk: walk the practice key instead of the run's key. */
export function choosePractice(on: boolean) {
  aesWalk.chosePractice = on
  refreshAesWalk()
}

/** Opens Techniques at the AES walk, on the block of a lesson's run. A lesson's tab always opens on that run's own block. */
export function openAesWalk(sessionId: string, lesson: number | null) {
  aesWalk.lesson = lesson
  aesWalk.sessionId = sessionId
  aesWalk.typed = ''
  aesWalk.chosePractice = false
  ui.walkItem = { ...ui.walkItem, techniques: 'aes' }
  ui.section = 'techniques'
  refreshAesWalk()
}

watch(() => sec.showKeys, on => {
  if (isPractice()) return
  if (!on) clearAesWalk()
  else if (aesWalk.sessionId && !aesWalk.block && !aesWalk.loading && hostState.value === 'connected') refreshAesWalk()
})

onSocketClose(() => {
  clearAesWalk()
  aesWalk.closedBySocket = true
})

watch(hostState, async s => {
  if (s !== 'connected' || aesWalk.block || !aesWalk.opened) return
  await loadSecurity()
  if (isPractice() || sec.showKeys) refreshAesWalk()
})
