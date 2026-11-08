import { computed, onBeforeUnmount, ref } from 'vue'

// The walk's one clock (docs/walkthrough-design.md section 2.2a). It owns every timer and every animation the walk starts.
// A view asks it for an animation or a delay and never calls setTimeout or el.animate itself, so Pause reaches everything,
// and an unmount (Show keys off, a new block) stops everything. A motion only moves between states the engine returned:
// the cells already hold the end frame, and the animation is decoration over it.

export type Speed = 'slow' | 'normal' | 'fast'
export const SPEEDS: readonly Speed[] = ['slow', 'normal', 'fast']
const FACTOR: Record<Speed, number> = { slow: 1.8, normal: 1, fast: 0.45 }

interface Timer { id: number; left: number; started: number; done: () => void }

const reducedQuery = typeof matchMedia === 'function' ? matchMedia('(prefers-reduced-motion: reduce)') : null

export function useWalkTimeline() {
  const speed = ref<Speed>('normal')
  const paused = ref(false)
  const playing = ref(false)
  // Bumped on each change to the animation set, so `running` recomputes. The set itself is not reactive.
  const tick = ref(0)
  const own = new Set<Animation>()
  const timers = new Set<Timer>()

  /** Read live at each call, so a change to the OS setting applies from the next step. */
  const reduced = () => !!reducedQuery?.matches
  const ms = (base: number) => base * FACTOR[speed.value]

  const running = computed(() => {
    void tick.value
    return playing.value || [...own].some(a => a.playState === 'running' || a.playState === 'paused')
  })
  /** The one button's word, by state (design 2.2a). */
  const buttonWord = computed(() => (paused.value ? 'Resume' : running.value ? 'Pause' : 'Play'))

  function forget(a: Animation) { own.delete(a); tick.value++ }

  /** Starts one animation. With reduced motion it starts none, so the step lands at once on its end frame. */
  function animate(el: Element, keyframes: Keyframe[], o: { duration: number; delay?: number; pseudo?: string; fill?: FillMode; easing?: string }): Animation | null {
    if (reduced()) return null
    const a = el.animate(keyframes, { duration: ms(o.duration), delay: ms(o.delay ?? 0), easing: o.easing ?? 'ease-in-out', fill: o.fill ?? 'both', pseudoElement: o.pseudo })
    own.add(a)
    if (paused.value) a.pause()
    tick.value++
    a.finished.then(() => { tick.value++ }, () => { /* a cancel is how Back and an unmount end a motion */ })
    return a
  }

  /** Resolves when every animation the clock started has finished. A paused animation holds the promise until Resume. */
  async function settle(): Promise<void> {
    while ([...own].some(a => a.playState !== 'finished' && a.playState !== 'idle')) {
      await Promise.all([...own].map(a => a.finished.catch(() => null)))
    }
  }

  /** A pausable wait. Pause records the time left, and Resume waits only that long. */
  function delay(base: number): Promise<void> {
    return new Promise(resolve => {
      const t: Timer = { id: 0, left: ms(base), started: 0, done: () => { timers.delete(t); resolve() } }
      timers.add(t)
      if (!paused.value) startTimer(t)
    })
  }
  function startTimer(t: Timer) { t.started = performance.now(); t.id = window.setTimeout(t.done, t.left) }

  /** A click during a motion: each animation jumps to its end frame. Play stops too. */
  function finishNow() {
    playing.value = false
    paused.value = false
    for (const a of own) if (a.playState !== 'finished') a.finish()
    tick.value++
  }

  /** Back, a new block, or an unmount: every animation and timer goes, and no mark is left behind. */
  function stopAll() {
    playing.value = false
    paused.value = false
    for (const a of own) a.cancel()
    own.clear()
    for (const t of timers) window.clearTimeout(t.id)
    timers.clear()
    tick.value++
  }

  /** Drops the finished animations of the last step, so their end-state fill does not linger into the next one. */
  function clearFinished() { for (const a of [...own]) if (a.playState === 'finished') { a.cancel(); forget(a) } }

  function pause() {
    if (paused.value) return
    paused.value = true
    for (const a of own) if (a.playState === 'running') a.pause()
    for (const t of timers) { window.clearTimeout(t.id); t.left = Math.max(0, t.left - (performance.now() - t.started)) }
    tick.value++
  }

  function resume() {
    if (!paused.value) return
    paused.value = false
    for (const a of own) if (a.playState === 'paused') a.play()
    for (const t of timers) startTimer(t)
    tick.value++
  }

  /** True while any animation the clock started is still moving or frozen. Play's own wait does not count. */
  const moving = () => [...own].some(a => a.playState === 'running' || a.playState === 'paused')

  onBeforeUnmount(stopAll)

  return { speed, paused, playing, running, buttonWord, reduced, animate, settle, delay, finishNow, stopAll, clearFinished, pause, resume, moving }
}
