<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { hostGet } from '../host'
import { addr } from '../store'
import { describe } from '../aesWalkState'
import { useStepper } from '../useStepper'
import { isO, ptAttrs, ptText, type EnginePoint, type ToyCurve, type ToyPick } from '../curveWalk'

// The same curve over GF(17), as the video draws it next (slice P8a; R7): a scatter of the engine's 18 points plus O. Pick any 2 dots and the
// engine adds them (GET /api/walk/toy-curve/add, by the points' index in its own list); the card shows its slope, inverse and sum (R5).
// Then k*G hops through the dots until it closes on O at the order.
const props = defineProps<{ toy: ToyCurve }>()

const N = computed(() => props.toy.curve.p)
const C = 21, LEFT = 30, TOP = 12
const W = computed(() => LEFT + N.value * C + 70)
const H = computed(() => TOP + N.value * C + 26)
const px = (x: number) => LEFT + x * C + C / 2
const py = (y: number) => TOP + (N.value - 1 - y) * C + C / 2
/** O has no place on the grid, so it sits in its own spot to the right. */
const O_AT = computed(() => ({ x: LEFT + N.value * C + 36, y: TOP + (N.value * C) / 2 }))
const at = (p: EnginePoint) => (isO(p) ? O_AT.value : { x: px(p.x), y: py(p.y) })
const ticks = computed(() => Array.from({ length: N.value }, (_, i) => i))

// ---- Picks: the first click is P, the second Q (the same dot twice is a double). A third click starts again.
const oIndex = computed(() => props.toy.points.length)
const picked = ref<number[]>([])
const sum = ref<ToyPick | null>(null)
const error = ref('')
const play = ref(0)
let gen = 0
async function pickDot(i: number) {
  if (picked.value.length >= 2) { picked.value = []; sum.value = null }
  picked.value = [...picked.value, i]
  error.value = ''
  if (picked.value.length < 2) { sum.value = null; return }
  const mine = ++gen
  const [p, q] = picked.value
  try {
    const r = await hostGet(addr, `/api/walk/toy-curve/add?p=${p}&q=${q}`) as ToyPick
    if (mine === gen) { sum.value = r; play.value++ }
  } catch (e: any) { if (mine === gen) error.value = `The engine could not add them: ${describe(e)}` }
}
const role = (i: number) => (picked.value[0] === i ? 'P' : picked.value[1] === i ? 'Q' : undefined)
const step = computed(() => sum.value?.step ?? null)

const lineEnds = computed(() => {
  const s = step.value
  if (!s || s.kind !== 'add') return null
  return { a: at(s.p), b: at(s.q) }
})
const pickNote = computed(() => {
  if (!picked.value.length) return 'Pick a dot for P, then a dot for Q. Pick the same dot twice to double it.'
  if (picked.value.length === 1) return 'Now pick Q.'
  const s = step.value
  if (!s) return error.value || 'Asking the engine.'
  if (s.kind === 'identity') return `One of them is O, the point at infinity. O adds nothing, so the sum is ${ptText(s.result)}.`
  if (isO(s.result)) return 'The line is vertical, so it meets no third point. The sum is O.'
  return s.kind === 'double' ? `P + P = ${ptText(s.result)}. The slope comes from the tangent at P.` : `P + Q = ${ptText(s.result)}.`
})

// ---- k*G hops: a marker walks from G through each multiple, and the 19th hop lands on O.
const { at: hop, playing, next: nextHop, all: allHops, play: playHops } = useStepper({ last: () => props.toy.hops.length - 1, intervalMs: 700, nextWraps: false, all: 'last' })
const hopPath = computed(() => {
  if (hop.value === null) return ''
  return props.toy.hops.slice(0, hop.value + 1).map((h, i) => { const p = at(h.point); return `${i ? 'L' : 'M'}${p.x},${p.y}` }).join(' ')
})
const hopNow = computed(() => (hop.value === null ? null : props.toy.hops[hop.value]))
const hopList = ref<HTMLElement | null>(null)
watch(hop, i => {
  const box = hopList.value, row = i === null ? null : box?.querySelector<HTMLElement>(`[data-testid="curve-hop-${i}"]`)
  if (box && row) box.scrollTop = row.offsetTop - box.offsetTop - box.clientHeight / 2
})
</script>

<template>
  <section class="cw-card" data-testid="curve-toy-card" aria-label="The curve over GF(17)">
    <h3>2. The same curve over GF(17): pick 2 dots and add them</h3>
    <p class="muted">Now every number is taken mod {{ toy.curve.p }}: y² = x³ + {{ toy.curve.a }}x + {{ toy.curve.b }} mod {{ toy.curve.p }}. The smooth curve turns into {{ toy.points.length }} dots, plus O. The chord rule still works. Only the arithmetic changes.</p>
    <div class="cw-toy">
      <svg :viewBox="`0 0 ${W} ${H}`" class="cw-svg cw-svg-toy" role="group" aria-label="The points of the curve. Pick 2 to add them.">
        <g class="cw-grid" aria-hidden="true">
          <line v-for="i in ticks" :key="`v${i}`" :x1="px(i)" :x2="px(i)" :y1="TOP" :y2="TOP + N * C" />
          <line v-for="i in ticks" :key="`h${i}`" :y1="py(i)" :y2="py(i)" :x1="LEFT" :x2="LEFT + N * C" />
          <text v-for="i in ticks" :key="`x${i}`" :x="px(i)" :y="TOP + N * C + 16" class="cw-tick">{{ i }}</text>
          <text v-for="i in ticks" :key="`y${i}`" :x="LEFT - 6" :y="py(i) + 4" class="cw-tick cw-tick-y">{{ i }}</text>
        </g>
        <path v-if="hopPath" :d="hopPath" class="cw-hop-path" />
        <g v-if="step" :key="play" class="cw-build">
          <line v-if="lineEnds" data-testid="curve-chord" :x1="lineEnds.a.x" :y1="lineEnds.a.y" :x2="lineEnds.b.x" :y2="lineEnds.b.y" class="cw-line" pathLength="1" />
          <g v-if="step.kind === 'double'" data-testid="curve-tangent" class="cw-tangent">
            <circle :cx="at(step.p).x" :cy="at(step.p).y" r="13" class="cw-tangent-ring" />
            <text :x="at(step.p).x + 16" :y="at(step.p).y - 12" class="cw-tag cw-tan-t">tangent at P</text>
          </g>
        </g>
        <g data-testid="curve-scatter">
          <circle v-for="(p, i) in toy.points" :key="i" :data-testid="`curve-point-${p.x}-${p.y}`" :data-x="String(p.x)" :data-y="String(p.y)" :data-picked="role(i)"
            :cx="px(p.x)" :cy="py(p.y)" r="6" class="cw-dot" :class="role(i) ? `cw-dot-${role(i)}` : ''" role="button" tabindex="0" :aria-label="`point (${p.x}, ${p.y})`"
            @click="pickDot(i)" @keydown.enter.prevent="pickDot(i)" @keydown.space.prevent="pickDot(i)" />
          <g class="cw-o">
            <circle data-testid="curve-point-O" data-point="O" :data-picked="role(oIndex)" :cx="O_AT.x" :cy="O_AT.y" r="12" class="cw-dot cw-dot-o" :class="role(oIndex) ? `cw-dot-${role(oIndex)}` : ''"
              role="button" tabindex="0" aria-label="O, the point at infinity" @click="pickDot(oIndex)" @keydown.enter.prevent="pickDot(oIndex)" @keydown.space.prevent="pickDot(oIndex)" />
            <text :x="O_AT.x" :y="O_AT.y + 4" class="cw-o-t" aria-hidden="true">O</text>
            <text :x="O_AT.x" :y="O_AT.y + 28" class="cw-tick" aria-hidden="true">infinity</text>
          </g>
        </g>
        <g v-if="step" :key="`r${play}`" class="cw-build">
          <circle data-testid="curve-point-r" v-bind="ptAttrs(step.result)" :cx="at(step.result).x" :cy="at(step.result).y" r="10" class="cw-r-ring" />
          <text :x="at(step.result).x + 12" :y="at(step.result).y + 16" class="cw-tag cw-r-t cw-late">R</text>
        </g>
        <circle v-if="hopNow" data-testid="curve-hop-marker" v-bind="ptAttrs(hopNow.point)" :cx="at(hopNow.point).x" :cy="at(hopNow.point).y" r="9" class="cw-hop-marker" />
      </svg>
      <div class="cw-toy-side">
        <p class="cw-cap" aria-live="polite" data-testid="curve-pick-note">{{ pickNote }}</p>
        <div v-if="step && step.lambda !== null && step.inverse" :key="play" class="cw-slope cw-build" data-testid="curve-slope">
          <p class="cw-formula">{{ step.kind === 'double' ? 'λ = (3·x_P² + a) / (2·y_P)' : 'λ = (y_Q − y_P) / (x_Q − x_P)' }}, mod {{ toy.curve.p }}</p>
          <p class="cw-line-in" style="--d: 0">Top: <b data-testid="curve-slope-num">{{ step.numerator }}</b>. Bottom: <b data-testid="curve-slope-den">{{ step.denominator }}</b>.</p>
          <p class="cw-line-in" style="--d: 1">There is no dividing mod {{ toy.curve.p }}. Multiply by the inverse of {{ step.denominator }} instead, found by the extended Euclid steps:</p>
          <table class="cw-euclid cw-line-in" style="--d: 2">
            <thead><tr><th>a</th><th>b</th><th>quotient</th><th>remainder</th><th>t</th></tr></thead>
            <tbody>
              <tr v-for="(r, i) in step.inverse.rows" :key="i" :data-testid="`curve-slope-euclid-${i}`"><td>{{ r.a }}</td><td>{{ r.b }}</td><td>{{ r.quotient }}</td><td>{{ r.remainder }}</td><td>{{ r.t }}</td></tr>
            </tbody>
          </table>
          <p class="cw-line-in" style="--d: 3">Inverse of {{ step.denominator }}: <b data-testid="curve-slope-inverse">{{ step.inverse.value }}</b></p>
          <p class="cw-line-in" style="--d: 4">λ = {{ step.numerator }} × {{ step.inverse.value }} mod {{ toy.curve.p }} = <b data-testid="curve-slope-lambda">{{ step.lambda }}</b></p>
          <p class="cw-line-in" style="--d: 5">x_R = λ² − x_P − x_Q, and y_R = λ·(x_P − x_R) − y_P, both mod {{ toy.curve.p }}. The engine gives R = <b>{{ ptText(step.result) }}</b>.</p>
        </div>
      </div>
    </div>

    <h3>3. k·G: hop from G through the dots</h3>
    <p class="muted">Start at G = {{ ptText(toy.hops[0]?.point) }}. Add G again and again. Each hop lands on a dot. After <span data-testid="curve-hop-count">{{ toy.curve.order }} hops (the order is {{ toy.curve.order }})</span>, it lands on O and the cycle starts again.</p>
    <div class="cw-controls">
      <v-btn color="primary" size="small" data-testid="curve-hops-play" @click="playHops">{{ playing ? 'Pause' : 'Play the hops' }}</v-btn>
      <v-btn size="small" data-testid="curve-hops-next" @click="nextHop">Next hop</v-btn>
      <v-btn size="small" variant="text" data-testid="curve-hops-all" @click="allHops">Show all</v-btn>
    </div>
    <ol ref="hopList" class="cw-hops" aria-label="k times G">
      <li v-for="(h, i) in toy.hops" :key="i" :data-testid="`curve-hop-${i}`" v-bind="ptAttrs(h.point)" :aria-current="hop === i ? 'true' : undefined" :class="{ seen: hop !== null && i <= hop }">
        <b>{{ h.k }}·G</b> = {{ ptText(h.point) }}<span v-if="h.step" class="muted"> ({{ h.step.kind === 'double' ? 'G + G' : `${h.k - 1}·G + G` }})</span>
      </li>
    </ol>
  </section>
</template>
