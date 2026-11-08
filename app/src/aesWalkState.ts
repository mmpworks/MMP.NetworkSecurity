import { reactive, watch } from 'vue'
import { hostGet } from './host'
import { loadSecurity, sec } from './security'
import { addr, hostState, onSocketClose, ui } from './store'
import type { AesBlockReply, AesTables } from './walk'

/** The key sizes the picker offers. The engine serves each one on the block route (design section 2.2b). */
export const KEY_SIZES = [128, 192, 256] as const
export type KeyBits = typeof KEY_SIZES[number]

// The AES block walk's state, and the flip-race rule of docs/walkthrough-design.md section 3.5:
// 1. A generation counter rises, and the walk clears, when Show keys goes off by any route and when the socket closes.
// 2. A reply from an old generation, or one that lands while Show keys is off, is dropped.
// 3. After a reconnect the app reads the toggle first, and fetches the walk again only when it is on.
// 4. A walk reply lives only here: it never enters a session, /events, or a save.
export const aesWalk = reactive({
  gen: 0,
  sessionId: '',
  lesson: null as number | null,
  block: null as AesBlockReply | null,
  keyBits: 128 as KeyBits,
  // The tables are public and hold no key byte, so they stay after a flip to OFF (design section 2.3).
  tables: null as AesTables | null,
  loading: false,
  error: '',
  closedBySocket: false,
})

export function clearAesWalk() {
  aesWalk.gen++
  aesWalk.block = null
  aesWalk.loading = false
}

export async function fetchAesBlock(sessionId: string) {
  aesWalk.sessionId = sessionId
  const gen = ++aesWalk.gen
  aesWalk.block = null
  aesWalk.error = ''
  aesWalk.closedBySocket = false
  if (!sec.showKeys) return
  aesWalk.loading = true
  try {
    // Chapter 1 is block 1 of the run's text, at the key size the picker holds (design sections 2.2b and 3.4).
    const [body] = await Promise.all([
      hostGet(addr, `/api/sessions/${encodeURIComponent(sessionId)}/walk/aes/block?source=text&keyBits=${aesWalk.keyBits}`),
      loadAesTables(),
    ])
    if (gen !== aesWalk.gen || !sec.showKeys) return
    aesWalk.block = body as AesBlockReply
  } catch (e: any) {
    if (gen === aesWalk.gen) aesWalk.error = String(e?.body?.message ?? e?.body?.code ?? (e?.status ? `HTTP_${e.status}` : 'WALK_FAILED'))
  } finally {
    if (gen === aesWalk.gen) aesWalk.loading = false
  }
}

/** The public tables, fetched once. The route stays open with Show keys off, so the closed walk can still show the S-box (design section 2.3). */
export async function loadAesTables(): Promise<AesTables> {
  if (!aesWalk.tables) aesWalk.tables = await hostGet(addr, '/api/walk/aes/tables') as AesTables
  return aesWalk.tables
}

/** The key size picker: the walk fetches the run's block again at the new size. */
export function pickKeyBits(bits: KeyBits) {
  if (bits === aesWalk.keyBits && aesWalk.block) return
  aesWalk.keyBits = bits
  if (aesWalk.sessionId) void fetchAesBlock(aesWalk.sessionId)
}

/** Opens Techniques at the AES walk, on the block of a lesson's run. */
export function openAesWalk(sessionId: string, lesson: number | null) {
  aesWalk.lesson = lesson
  ui.walkItem = { ...ui.walkItem, techniques: 'aes' }
  ui.section = 'techniques'
  void fetchAesBlock(sessionId)
}

watch(() => sec.showKeys, on => {
  if (!on) clearAesWalk()
  else if (aesWalk.sessionId && !aesWalk.block && !aesWalk.loading && hostState.value === 'connected') void fetchAesBlock(aesWalk.sessionId)
})

onSocketClose(() => {
  clearAesWalk()
  aesWalk.closedBySocket = !!aesWalk.sessionId
})

watch(hostState, async s => {
  if (s !== 'connected' || !aesWalk.sessionId || aesWalk.block) return
  await loadSecurity()
  if (sec.showKeys) void fetchAesBlock(aesWalk.sessionId)
})
