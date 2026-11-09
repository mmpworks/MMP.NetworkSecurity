// One GET walk route for a screen: the reply, the error line, and a reload. The Handshake key schedule walks take no input, so one call
// gives the whole walk. Every value the screen shows comes from the reply (R5): the app computes nothing.
import { reactive, watch } from 'vue'
import { describe } from './aesWalkState'
import { hostGet } from './host'
import { addr, hostState } from './store'

export interface WalkFetch<T> { data: T | null; error: string; loading: boolean; load: () => Promise<void> }

/** Loads the route now, and again each time the Host comes back, so a screen opened while the Host was down fills in by itself. */
export function useWalk<T>(route: string): WalkFetch<T> {
  const w = reactive({ data: null, error: '', loading: false }) as { data: T | null; error: string; loading: boolean }
  let gen = 0
  async function load() {
    const mine = ++gen
    w.loading = true
    w.error = ''
    try {
      const body = await hostGet(addr, route) as T
      if (mine === gen) w.data = body
    } catch (e: any) {
      if (mine === gen) w.error = `${route} failed: ${describe(e)}`
    } finally {
      if (mine === gen) w.loading = false
    }
  }
  watch(hostState, s => { if (s === 'connected' && !w.data) void load() })
  void load()
  return Object.assign(w, { load })
}
