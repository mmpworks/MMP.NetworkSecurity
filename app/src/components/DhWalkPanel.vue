<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'
import { useWalk } from '../walkFetch'

// The Diffie-Hellman walk (slice P7; docs/sections-plan.md section 5; mock v28's DH tab, with Steve's paint chips). The engine runs both
// sides on a public practice exponent (GET /api/walk/dh), so the walk stays open with Show keys off. Every number is the engine's (R5):
// the screen shows the reply's decimal (small prime) or hex (group 14) and computes nothing. Where the mock shows the chain of powers
// g^1, g^2, ..., the walk shows the engine's own square-and-multiply rows, which is how it raises a 32-bit exponent.
interface Num { hex: string; dec: string }
interface Row { bit: number; isOne: boolean; afterSquare: Num | null; afterMultiply: Num | null }
interface Pow { base: Num; exponent: Num; result: Num; rows: Row[] }
interface Side { private: Num; public: Pow; shared: Pow }
interface Reply { group: string; prime: Num; generator: Num; realExponentBits: number; client: Side; server: Side }

const walks = { small: useWalk<Reply>('/api/walk/dh?group=small'), group14: useWalk<Reply>('/api/walk/dh?group=group14') }
const group = ref<'small' | 'group14'>('small')
const walk = computed(() => walks[group.value])
const w = computed(() => walk.value.data)

/** A number as the engine sent it: decimal on the small prime, so it can be read; hex on group 14, where decimal runs to 617 digits. */
const show = (n: Num | null | undefined) => (!n ? '' : group.value === 'small' ? n.dec : n.hex)

// ---- The chips (Steve, mock v28): one paint per value, a DH letter so colour never carries meaning alone, and a legend.
interface Chip { colour: string; letter: string; says: string }
const CHIP: Record<string, Chip> = {
  'client-private': { colour: 'red', letter: 'a', says: "the client's private number" },
  'server-private': { colour: 'blue', letter: 'b', says: "the server's private number" },
  g: { colour: 'yellow', letter: 'g', says: 'the public base' },
  'client-public': { colour: 'orange', letter: 'A', says: "the client's public number" },
  'server-public': { colour: 'green', letter: 'B', says: "the server's public number" },
  'from-client': { colour: 'orange', letter: 'A', says: "the client's public number, received" },
  'from-server': { colour: 'green', letter: 'B', says: "the server's public number, received" },
  'client-shared': { colour: 'brown', letter: 's', says: 'the shared secret' },
  'server-shared': { colour: 'brown', letter: 's', says: 'the shared secret' },
}
const LEGEND: { colour: string; letter: string; says: string }[] = [
  { colour: 'red', letter: 'a', says: "client's private number" }, { colour: 'blue', letter: 'b', says: "server's private number" },
  { colour: 'yellow', letter: 'g', says: 'the public base' }, { colour: 'orange', letter: 'A', says: "client's public number" },
  { colour: 'green', letter: 'B', says: "server's public number" }, { colour: 'brown', letter: 's', says: 'the shared secret, the same on both sides' },
]

// ---- The steps, as in the mock: null shows the whole exchange.
const LAST = 8
const step = ref<number | null>(null)
const at = (n: number) => step.value === null || step.value >= n
let timer = 0
const playing = ref(false)
function stop() { playing.value = false; window.clearTimeout(timer) }
function next() { stop(); step.value = step.value === null || step.value >= LAST ? 0 : step.value + 1 }
function all() { stop(); step.value = null }
function play() {
  if (playing.value) { stop(); return }
  playing.value = true
  if (step.value === null || step.value >= LAST) step.value = 0
  const tick = () => {
    if (!playing.value) return
    if ((step.value ?? 0) >= LAST) { playing.value = false; return }
    step.value = (step.value ?? 0) + 1
    timer = window.setTimeout(tick, 2200)
  }
  timer = window.setTimeout(tick, 2200)
}
onBeforeUnmount(stop)
function pickGroup(g: 'small' | 'group14') { stop(); group.value = g; step.value = null }

/** A long group 14 number in a caption or a row shows its ends, so it stays one line. The whole number is in the value rows below. */
const short = (n: Num | null) => { const t = show(n); return group.value === 'group14' && t.length > 28 ? `${t.slice(0, 16)}…${t.slice(-8)}` : t }

/** The caption of a step, with the engine's numbers, in the short form on group 14. */
const caption = computed(() => {
  const v = w.value
  if (!v) return null
  const n = short(v.prime), g = short(v.generator), a = short(v.client.private), b = short(v.server.private)
  const A = short(v.client.public.result), B = short(v.server.public.result), s1 = short(v.client.shared.result), s2 = short(v.server.shared.result)
  const words: [string, string][] = [
    ['Both sides agree on n and g', 'These two numbers are public. Anyone may read them. Often a standard fixes them in advance.'],
    ['The client picks a private number', 'It never leaves the client. Not even the server sees it.'],
    ['The server picks a private number', 'It never leaves the server.'],
    [`Client: ${g} to the power ${a}, mod ${n} = ${A}`, `Mod ${n} means: keep the remainder after dividing by ${n}, like a clock with ${n} hours. Going forward is easy. The rows below are the engine's square and multiply, one per bit of the private number.`],
    [`Server: ${g} to the power ${b}, mod ${n} = ${B}`, 'The server does the same with its own private number.'],
    [`The client sends ${A}`, 'This number crosses the wire. The listener reads it.'],
    [`The server sends ${B}`, 'This one crosses too. The listener now has all four public numbers.'],
    [`Client: ${B} to the power ${a}, mod ${n} = ${s1}`, "The client uses the server's public number and its own private number."],
    [`Server: ${A} to the power ${b}, mod ${n} = ${s2}`, `The answers match, because both are ${g} to the power a times b. The secret never crossed the wire.`],
  ]
  if (step.value === null) return { top: `Both sides hold ${s1}, and it never crossed the wire.`, sub: 'Press Play to step through it, or Next for one step at a time.' }
  return { top: words[step.value][0], sub: words[step.value][1] }
})

/** The power a step works, from the engine: g^a and g^b, then B^a and A^b. Other steps work none. */
const power = computed<Pow | null>(() => {
  const v = w.value
  if (!v || step.value === null) return null
  return ({ 3: v.client.public, 4: v.server.public, 7: v.client.shared, 8: v.server.shared } as Record<number, Pow>)[step.value] ?? null
})

/** This walk's own exponent size, from the length of the engine's private number: 8 bits on the small prime, 32 on group 14. */
const expBits = computed(() => (w.value ? (w.value.client.private.hex.length / 2) * 8 : 0))

// ---- The paint picture, as in the mock: it fills as the steps go.
const paint = computed(() => {
  const v = step.value === null ? LAST : step.value
  return [
    { who: 'Client', parts: [['yellow', v >= 0], ['red', v >= 1]], out: ['orange', v >= 3] },
    { who: 'Server', parts: [['yellow', v >= 0], ['blue', v >= 2]], out: ['green', v >= 4] },
    { who: 'Client', parts: [['green', v >= 6], ['red', v >= 7]], out: ['brown', v >= 7] },
    { who: 'Server', parts: [['orange', v >= 5], ['blue', v >= 8]], out: ['brown', v >= 8] },
  ] as { who: string; parts: [string, boolean][]; out: [string, boolean] }[]
})
</script>

<template>
  <div class="dh" data-testid="dh-walk-panel">
    <header class="dh-head">
      <h2>Diffie-Hellman: agree on a secret in public</h2>
      <p class="muted">AES needs both sides to hold one key. They never send it. Each side keeps a private number and sends a public one, and then both work out the same secret.</p>
      <div class="dh-groups" role="group" aria-label="Which group">
        <button type="button" class="dh-group" :aria-pressed="group === 'small'" data-testid="dh-group-small" @click="pickGroup('small')">Small prime, to read</button>
        <button type="button" class="dh-group" :aria-pressed="group === 'group14'" data-testid="dh-group-group14" @click="pickGroup('group14')">Group 14, the real size</button>
      </div>
      <p v-if="w" class="dh-note" data-testid="dh-real-size">This walk uses {{ /^(8|11|18)/.test(String(expBits)) ? 'an' : 'a' }} {{ expBits }}-bit practice exponent. Lesson 8's real exchange uses <span data-testid="dh-real-size-bits">{{ w.realExponentBits }}</span>-bit exponents.</p>
    </header>
    <p v-if="walk.error" class="walk-error" data-testid="dh-walk-error">{{ walk.error }} <button type="button" class="retry" @click="walk.load()">Try again</button></p>
    <p v-else-if="!w" class="muted">Loading the exchange from the engine.</p>
    <template v-else>
      <div class="dh-controls">
        <v-btn color="primary" size="small" data-testid="dh-play" @click="play">{{ playing ? 'Pause' : 'Play the exchange' }}</v-btn>
        <v-btn size="small" data-testid="dh-next" @click="next">Next</v-btn>
        <v-btn size="small" variant="text" data-testid="dh-all" @click="all">Show all</v-btn>
      </div>
      <div v-if="caption" class="dh-cap" data-testid="dh-caption" aria-live="polite"><b>{{ caption.top }}</b><span>{{ caption.sub }}</span></div>
      <div class="dh-cols">
        <section class="dh-side" aria-label="Client">
          <h3>Client</h3>
          <div class="dh-row" data-testid="dh-value-client-private">
            <span class="dh-label">Private number</span>
            <span class="dh-val"><span class="dh-chip" :data-chip="CHIP['client-private'].colour" :data-letter="CHIP['client-private'].letter" :aria-label="`${CHIP['client-private'].colour} chip: ${CHIP['client-private'].says}`" data-testid="dh-chip-client-private">a</span><span class="dh-num dh-secret-num" data-testid="dh-value-client-private-number">{{ at(1) ? show(w.client.private) : '?' }}</span></span>
          </div>
          <div v-if="at(3)" class="dh-row" data-testid="dh-value-client-public">
            <span class="dh-label">Public number</span>
            <span class="dh-val"><span class="dh-chip" data-chip="orange" data-letter="A" :aria-label="`orange chip: ${CHIP['client-public'].says}`" data-testid="dh-chip-client-public">A</span><span class="dh-num" data-testid="dh-value-client-public-number">{{ show(w.client.public.result) }}</span></span>
          </div>
          <div v-if="at(6)" class="dh-row">
            <span class="dh-label">From the server</span>
            <span class="dh-val"><span class="dh-chip" data-chip="green" data-letter="B" :aria-label="`green chip: ${CHIP['from-server'].says}`" data-testid="dh-chip-from-server">B</span><span class="dh-num">{{ show(w.server.public.result) }}</span></span>
          </div>
          <div v-if="at(7)" class="dh-row dh-row-secret" data-testid="dh-value-client-shared">
            <span class="dh-label">Secret</span>
            <span class="dh-val"><span class="dh-chip" data-chip="brown" data-letter="s" :aria-label="`brown chip: ${CHIP['client-shared'].says}`" data-testid="dh-chip-client-shared">s</span><span class="dh-num" data-testid="dh-value-client-shared-number">{{ show(w.client.shared.result) }}</span></span>
          </div>
        </section>
        <section class="dh-side dh-wire" aria-label="On the wire">
          <h3>On the wire: the listener reads all of this</h3>
          <div class="dh-row" data-testid="dh-value-n">
            <span class="dh-label">n, the prime</span>
            <span class="dh-val"><span class="dh-num" data-testid="dh-value-n-number">{{ show(w.prime) }}</span></span>
          </div>
          <div class="dh-row" data-testid="dh-value-g">
            <span class="dh-label">g, the base</span>
            <span class="dh-val"><span class="dh-chip" data-chip="yellow" data-letter="g" :aria-label="`yellow chip: ${CHIP.g.says}`" data-testid="dh-chip-g">g</span><span class="dh-num" data-testid="dh-value-g-number">{{ show(w.generator) }}</span></span>
          </div>
          <div v-if="at(5)" class="dh-row">
            <span class="dh-label">Client sends</span>
            <span class="dh-val"><span class="dh-chip" data-chip="orange" data-letter="A" aria-label="orange chip: the client's public number, on the wire">A</span><span class="dh-num">{{ show(w.client.public.result) }}</span></span>
          </div>
          <div v-if="at(6)" class="dh-row">
            <span class="dh-label">Server sends</span>
            <span class="dh-val"><span class="dh-chip" data-chip="green" data-letter="B" aria-label="green chip: the server's public number, on the wire">B</span><span class="dh-num">{{ show(w.server.public.result) }}</span></span>
          </div>
        </section>
        <section class="dh-side" aria-label="Server">
          <h3>Server</h3>
          <div class="dh-row" data-testid="dh-value-server-private">
            <span class="dh-label">Private number</span>
            <span class="dh-val"><span class="dh-chip" data-chip="blue" data-letter="b" :aria-label="`blue chip: ${CHIP['server-private'].says}`" data-testid="dh-chip-server-private">b</span><span class="dh-num dh-secret-num" data-testid="dh-value-server-private-number">{{ at(2) ? show(w.server.private) : '?' }}</span></span>
          </div>
          <div v-if="at(4)" class="dh-row" data-testid="dh-value-server-public">
            <span class="dh-label">Public number</span>
            <span class="dh-val"><span class="dh-chip" data-chip="green" data-letter="B" :aria-label="`green chip: ${CHIP['server-public'].says}`" data-testid="dh-chip-server-public">B</span><span class="dh-num" data-testid="dh-value-server-public-number">{{ show(w.server.public.result) }}</span></span>
          </div>
          <div v-if="at(5)" class="dh-row">
            <span class="dh-label">From the client</span>
            <span class="dh-val"><span class="dh-chip" data-chip="orange" data-letter="A" :aria-label="`orange chip: ${CHIP['from-client'].says}`" data-testid="dh-chip-from-client">A</span><span class="dh-num">{{ show(w.client.public.result) }}</span></span>
          </div>
          <div v-if="at(8)" class="dh-row dh-row-secret" data-testid="dh-value-server-shared">
            <span class="dh-label">Secret</span>
            <span class="dh-val"><span class="dh-chip" data-chip="brown" data-letter="s" :aria-label="`brown chip: ${CHIP['server-shared'].says}`" data-testid="dh-chip-server-shared">s</span><span class="dh-num" data-testid="dh-value-server-shared-number">{{ show(w.server.shared.result) }}</span></span>
          </div>
        </section>
      </div>
      <!-- The engine's square and multiply for the power in play: one row per bit of the exponent, high bit first. -->
      <section v-if="power" class="dh-rows" aria-label="Square and multiply">
        <h3>How the engine raises {{ short(power.base) }} to the power {{ short(power.exponent) }}: square, then multiply when the bit is 1</h3>
        <ol>
          <li v-for="(r, i) in power.rows" :key="i" class="dh-rowline" :data-testid="`dh-row-${i}`">
            <span class="dh-bit" :class="{ on: r.isOne }">bit {{ r.isOne ? 1 : 0 }}</span>
            <span>square: <code>{{ short(r.afterSquare) }}</code></span>
            <span v-if="r.isOne">times {{ short(power.base) }}: <code>{{ short(r.afterMultiply) }}</code></span>
            <span v-else class="muted">no multiply</span>
          </li>
        </ol>
      </section>
      <section class="dh-paint" aria-label="The same idea in paint">
        <h3>The same idea in paint</h3>
        <p class="muted">Mixing paint is easy, and unmixing it is hard. Each side adds its private colour to the shared one and sends the mix. Then each adds its private colour to the other's mix. This is a picture of the idea, not the math.</p>
        <div v-for="(row, i) in paint" :key="i" class="dh-paint-row">
          <b>{{ row.who }}</b>
          <template v-for="(p, j) in row.parts" :key="j"><span v-if="j" aria-hidden="true"> + </span><span class="dh-dot" :data-chip="p[1] ? p[0] : undefined" :class="{ empty: !p[1] }" :aria-label="p[1] ? `${p[0]} paint` : 'not yet'" role="img" /></template>
          <span aria-hidden="true"> = </span><span class="dh-dot" :data-chip="row.out[1] ? row.out[0] : undefined" :class="{ empty: !row.out[1] }" :aria-label="row.out[1] ? `${row.out[0]} paint` : 'not yet'" role="img" />
        </div>
      </section>
      <section class="dh-legend" data-testid="dh-chip-legend" aria-label="What each colour means">
        <h3>The colours</h3>
        <ul>
          <li v-for="l in LEGEND" :key="l.colour"><span class="dh-chip" :data-chip="l.colour" aria-hidden="true">{{ l.letter }}</span> {{ l.colour }}: {{ l.letter }}, {{ l.says }}</li>
        </ul>
        <p class="muted">n, the prime, has no colour: it is not paint, it is the size of the clock.</p>
      </section>
    </template>
  </div>
</template>
