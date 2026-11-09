<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useWalk, type WalkFetch } from '../walkFetch'

// The X25519 walk (slice P8; docs/sections-plan.md section 4): the Montgomery ladder on the real engine, one row per bit, on RFC 7748
// section 6.1's public test scalars (GET /api/walk/x25519). Each row shows the bit, the swap, and the 2 points R0 = (x2 : z2) and
// R1 = (x3 : z3) after the step. Every value is the engine's (R5); the hex is little-endian, as RFC 7748 writes it.
interface Row { bit: number; isOne: boolean; swap: boolean; x2: string; z2: string; x3: string; z3: string; u2: string; u3: string }
interface Reply { step: string; scalar: string; clamped: string; point: string; result: string; rows: Row[] }

const STEPS = [
  { id: 'alice-public', label: "Alice's public key", says: "Alice's private scalar times the base point u = 9." },
  { id: 'bob-public', label: "Bob's public key", says: "Bob's private scalar times the base point u = 9." },
  { id: 'shared', label: 'The shared secret', says: "Alice's private scalar times Bob's public key." },
] as const
type StepId = typeof STEPS[number]['id']
const walks = Object.fromEntries(STEPS.map(s => [s.id, useWalk<Reply>(`/api/walk/x25519?step=${s.id}`)])) as Record<StepId, WalkFetch<Reply>>
const stepId = ref<StepId>('alice-public')
const walk = computed(() => walks[stepId.value])
const w = computed(() => walk.value.data)
const stepInfo = computed(() => STEPS.find(s => s.id === stepId.value)!)

// ---- Stepping: Next moves one row; Play moves on by itself.
const at = ref<number | null>(null)
const playing = ref(false)
let timer: number | undefined
const last = computed(() => (w.value ? w.value.rows.length - 1 : 0))
function stop() { playing.value = false; if (timer !== undefined) window.clearTimeout(timer); timer = undefined }
function advance() { at.value = at.value === null ? 0 : Math.min(at.value + 1, last.value) }
function next() { stop(); advance() }
function all() { stop(); at.value = last.value }
function play() {
  if (playing.value) { stop(); return }
  if (at.value === last.value) at.value = null
  playing.value = true
  const tick = () => { if (!playing.value) return; advance(); if (at.value === last.value) { playing.value = false; return } timer = window.setTimeout(tick, 450) }
  tick()
}
function pick(id: StepId) { stop(); stepId.value = id; at.value = null }
onBeforeUnmount(stop)
const now = computed(() => (w.value && at.value !== null ? w.value.rows[at.value] : null))

const list = ref<HTMLElement | null>(null)
watch(at, i => {
  const box = list.value, row = i === null ? null : box?.querySelector<HTMLElement>(`[data-testid="x25519-row-${i}"]`)
  if (box && row) box.scrollTop = row.offsetTop - box.offsetTop - box.clientHeight / 2
})
const short = (h: string | null) => (h ? `${h.slice(0, 8)}…${h.slice(-6)}` : "none yet")
</script>

<template>
  <!-- The panel takes its test id once the rows are in, so a reader who counts rows on sight counts all 255. -->
  <div class="cw x25519" :data-testid="w ? 'x25519-walk-panel' : undefined" :aria-busy="!w && !walk.error">
    <header class="cw-head">
      <h2>X25519: the Montgomery ladder, bit by bit</h2>
      <p class="muted">X25519 multiplies a point by a 255-bit number with the ladder from the curve walk. Every bit costs one add and one double, so the time gives no bit away. These are RFC 7748's public test numbers.</p>
      <div class="cw-picks" role="group" aria-label="Which multiplication">
        <button v-for="s in STEPS" :key="s.id" type="button" class="cw-pick" :aria-pressed="stepId === s.id" :data-testid="`x25519-step-${s.id}`" @click="pick(s.id)">{{ s.label }}</button>
      </div>
    </header>
    <p v-if="walk.error" class="walk-error">{{ walk.error }} <button type="button" class="retry" @click="walk.load()">Try again</button></p>
    <p v-else-if="!w" class="muted">Loading the ladder from the engine.</p>
    <template v-else>
      <dl class="x-facts">
        <dt>What it works out</dt><dd>{{ stepInfo.says }}</dd>
        <dt>Scalar</dt><dd><code>{{ w.scalar }}</code></dd>
        <dt>Clamped</dt><dd><code>{{ w.clamped }}</code> <span class="muted">(RFC 7748 clears the low 3 bits and the top bit, and sets bit 254)</span></dd>
        <dt>Point u</dt><dd><code>{{ w.point }}</code></dd>
      </dl>
      <div class="cw-controls">
        <v-btn color="primary" size="small" data-testid="x25519-play" @click="play">{{ playing ? 'Pause' : 'Play the ladder' }}</v-btn>
        <v-btn size="small" data-testid="x25519-next" @click="next">Next bit</v-btn>
        <v-btn size="small" variant="text" data-testid="x25519-all" @click="all">Go to the end</v-btn>
      </div>
      <div class="x-body">
        <ol ref="list" class="x-rows" aria-label="One row per bit">
          <li v-for="(r, i) in w.rows" :key="i" :data-testid="`x25519-row-${i}`" :aria-current="at === i ? 'true' : undefined" :class="{ seen: at !== null && i <= at }">
            <span class="x-bitno">bit {{ r.bit }}</span>
            <b class="x-bit" :data-testid="`x25519-bit-${i}`">{{ r.isOne ? '1' : '0' }}</b>
            <span class="x-swap" :data-testid="`x25519-swap-${i}`" :data-swap="String(r.swap)">{{ r.swap ? 'swap' : 'no swap' }}</span>
            <code class="x-u">u of R0 {{ short(r.u2) }}</code>
          </li>
        </ol>
        <section class="x-now" aria-live="polite" data-testid="x25519-now">
          <template v-if="now">
            <h3>Bit {{ now.bit }} is {{ now.isOne ? 1 : 0 }}: {{ now.swap ? 'swap R0 and R1, step, swap back' : 'no swap, just step' }}</h3>
            <div :key="at!" class="x-regs" :class="{ swapped: now.swap }">
              <div class="x-reg x-r0"><b>R0 = (x2 : z2)</b><span>x2 <code data-testid="x25519-now-x2">{{ now.x2 }}</code></span><span>z2 <code>{{ now.z2 }}</code></span><span>u <code>{{ now.u2 }}</code></span></div>
              <div class="x-reg x-r1"><b>R1 = (x3 : z3)</b><span>x3 <code>{{ now.x3 }}</code></span><span>z3 <code>{{ now.z3 }}</code></span><span>u <code>{{ now.u3 }}</code></span></div>
            </div>
            <p class="muted cw-small">Each step adds R0 and R1 into one of them and doubles the other. R1 − R0 stays the starting point, so the add needs no y.</p>
          </template>
          <p v-else class="muted">Press Play or Next bit to climb the ladder from bit 254 down to bit 0.</p>
        </section>
      </div>
      <p class="x-result">Result, the u of R0 after bit 0: <code data-testid="x25519-result">{{ w.result }}</code></p>
    </template>
  </div>
</template>
