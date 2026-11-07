import { reactive, watch } from 'vue'
import { hostGet } from './host'
import { loadSecurity, sec } from './security'
import { addr, hostState, onSocketClose, ui } from './store'
import type { AesBlockReply } from './walk'

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
    const body = await hostGet(addr, `/api/sessions/${encodeURIComponent(sessionId)}/walk/aes/block`)
    if (gen !== aesWalk.gen || !sec.showKeys) return
    aesWalk.block = body as AesBlockReply
  } catch (e: any) {
    if (gen === aesWalk.gen) aesWalk.error = String(e?.body?.code ?? (e?.status ? `HTTP_${e.status}` : 'WALK_FAILED'))
  } finally {
    if (gen === aesWalk.gen) aesWalk.loading = false
  }
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
