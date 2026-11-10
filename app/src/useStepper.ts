import { onBeforeUnmount, ref, type Ref } from 'vue'

// The step control the walk screens share (issue #363): Play / Pause, Next and Show all over steps 0..last. It owns its one timer and stops
// it on unmount. `at` is the step on screen. Null means no step is picked, which each screen reads in its own way: the Diffie-Hellman walk
// shows its whole exchange at null, and the hops and the X25519 ladder show none of their steps.
// useWalkTimeline is a different job: it owns the AES walk's animations and delays, not a step index.

export interface StepperOptions {
  /** The last step, read at each call, so it follows a reply that loads later. */
  last: () => number
  /** The pause between two steps while playing. */
  intervalMs: number
  /** Next on the last step goes back to step 0 (true) or stays on the last step (false). */
  nextWraps: boolean
  /** Show all goes to the last step ('last') or back to null ('none'). */
  all: 'last' | 'none'
}

export interface Stepper {
  at: Ref<number | null>
  playing: Ref<boolean>
  next: () => void
  all: () => void
  play: () => void
  stop: () => void
  /** Stops, and goes back to null: a new input (a group, a multiplication) starts its walk again. */
  reset: () => void
}

export function useStepper(o: StepperOptions): Stepper {
  const at = ref<number | null>(null)
  const playing = ref(false)
  let timer: number | undefined

  function stop() {
    playing.value = false
    if (timer !== undefined) window.clearTimeout(timer)
    timer = undefined
  }
  /** One step on. Null starts at 0; the last step wraps or stays, as the options say. */
  function step() {
    const last = o.last()
    if (at.value === null) at.value = 0
    else if (at.value >= last) at.value = o.nextWraps ? 0 : last
    else at.value += 1
  }
  function next() { stop(); step() }
  function all() { stop(); at.value = o.all === 'last' ? o.last() : null }
  function reset() { stop(); at.value = null }
  /** Play starts at step 0 when nothing is picked or the walk is at its end; otherwise it moves on from the step on screen. */
  function play() {
    if (playing.value) { stop(); return }
    playing.value = true
    if (at.value === null || at.value >= o.last()) at.value = 0
    else step()
    /** Plays stop on the last step, so Pause turns back into Play as the walk ends. */
    const schedule = () => { if ((at.value ?? 0) >= o.last()) stop(); else timer = window.setTimeout(tick, o.intervalMs) }
    const tick = () => { if (!playing.value) return; step(); schedule() }
    schedule()
  }
  onBeforeUnmount(stop)
  return { at, playing, next, all, play, stop, reset }
}
