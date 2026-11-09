<script setup lang="ts">
import { computed, ref } from 'vue'
import { useWalk } from '../walkFetch'
import { dec3, type RealCurve, type RealPoint, type RealSample } from '../curveWalk'

// The chord rule on the real curve y² = x³ + 2x + 2 (slice P8a; R7, the start of video 4Tfmwxr0I34). The engine sends the curve as points to
// draw and each example's P, Q, R' and R (GET /api/walk/real-curve). The card draws them in the video's order: P and Q, the line, the third
// point R', then the flip to R. It computes no point: a line is drawn between engine points, and a pixel place is only a scale.
const walk = useWalk<RealCurve>('/api/walk/real-curve')
const w = computed(() => walk.data)

/** Which example shows: the engine's chord, its tangent, or one of its offered picks. */
const pick = ref<'chord' | 'tangent' | number>('chord')
/** Bumps on each pick, so the drawing plays again. */
const play = ref(0)
function choose(p: 'chord' | 'tangent' | number) { pick.value = p; play.value++ }

const sample = computed<RealSample | null>(() => {
  const v = w.value
  if (!v) return null
  return pick.value === 'chord' ? v.chord : pick.value === 'tangent' ? v.tangent : v.samples[pick.value] ?? null
})

// ---- The picture's frame: the curve's own points and every example point fit inside it.
const W = 520, H = 360, PAD = 24
const frame = computed(() => {
  const v = w.value
  if (!v) return null
  const all: RealPoint[] = [...v.upper, ...v.lower, ...[v.chord, v.tangent, ...v.samples].flatMap(s => [s.p, s.q, s.rPrime, s.r])]
  const xs = all.map(p => p.x), ys = all.map(p => Math.abs(p.y))
  const x0 = Math.min(...xs) - 0.3, x1 = Math.max(...xs) + 0.3, y1 = Math.max(...ys) + 0.4
  return { x0, x1, y1 }
})
const sx = (x: number) => { const f = frame.value!; return PAD + ((x - f.x0) / (f.x1 - f.x0)) * (W - 2 * PAD) }
const sy = (y: number) => { const f = frame.value!; return H / 2 - (y / f.y1) * (H / 2 - PAD) }
/** An arrow head that ends 9 pixels short of R, pointing down (dir 1) or up (dir -1), so the flip reads as a move from R' to R. */
const arrow = (x: number, y: number, dir: number) => { const tip = y - dir * 9; return `${x - 5},${tip - dir * 8} ${x + 5},${tip - dir * 8} ${x},${tip}` }
const path = (pts: RealPoint[]) => pts.map((p, i) => `${i ? 'L' : 'M'}${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join(' ')

/**
 * The drawn line runs through the two outer points of P, Q and R' (for a tangent, P and R'), so it passes all three, and it runs on past
 * each end by a third of its length so it reads as a line, not a segment. This is drawing only: no point of the curve comes from it.
 */
const line = computed(() => {
  const s = sample.value
  if (!s) return null
  const pts = (s.kind === 'tangent' ? [s.p, s.rPrime] : [s.p, s.q, s.rPrime]).slice().sort((a, b) => a.x - b.x)
  const a = pts[0], b = pts[pts.length - 1], dx = (b.x - a.x) / 3, dy = (b.y - a.y) / 3
  return { a: { x: a.x - dx, y: a.y - dy }, b: { x: b.x + dx, y: b.y + dy } }
})

const caption = computed(() => {
  const s = sample.value
  if (!s) return ''
  return s.kind === 'tangent'
    ? `Doubling: P + P. The line is the tangent at P, slope ${dec3(s.lambda)}. It meets the curve once more at R'. Flip R' over the x-axis to get R = 2P.`
    : `Adding: P + Q. The line through P and Q has slope ${dec3(s.lambda)}. It meets the curve at a third point, R'. Flip R' over the x-axis to get R = P + Q.`
})
const label = (s: RealSample, i: number) => `Pick ${i + 1}: ${s.kind === 'tangent' ? 'a tangent' : 'a chord'}`
</script>

<template>
  <section class="cw-card" data-testid="curve-real-card" aria-label="The chord rule on the real curve">
    <h3>1. The chord rule, on the real numbers</h3>
    <p class="muted">The curve is y² = x³ + 2x + 2. To add two points, draw the line through them. It meets the curve at one more point. Flip that point over the x-axis.</p>
    <p v-if="walk.error" class="walk-error">{{ walk.error }} <button type="button" class="retry" @click="walk.load()">Try again</button></p>
    <p v-else-if="!w || !frame" class="muted">Loading the curve from the engine.</p>
    <template v-else>
      <div class="cw-picks" role="group" aria-label="Which example">
        <button type="button" class="cw-pick" :aria-pressed="pick === 'chord'" data-testid="curve-real-pick-chord" @click="choose('chord')">P + Q, a chord</button>
        <button type="button" class="cw-pick" :aria-pressed="pick === 'tangent'" data-testid="curve-real-pick-tangent" @click="choose('tangent')">P + P, a tangent</button>
        <button v-for="(s, i) in w.samples" :key="i" type="button" class="cw-pick" :aria-pressed="pick === i" :data-testid="`curve-real-sample-${i}`" @click="choose(i)">{{ label(s, i) }}</button>
      </div>
      <div class="cw-real">
        <svg :viewBox="`0 0 ${W} ${H}`" class="cw-svg" role="img" :aria-label="caption">
          <line :x1="PAD" :x2="W - PAD" :y1="H / 2" :y2="H / 2" class="cw-axis" />
          <line :x1="sx(0)" :x2="sx(0)" :y1="PAD / 2" :y2="H - PAD / 2" class="cw-axis" />
          <path :d="path(w.upper)" class="cw-curve" />
          <path :d="path(w.lower)" class="cw-curve" />
          <g v-if="sample && line" :key="play" class="cw-build">
            <line v-if="sample.kind === 'tangent'" data-testid="curve-real-tangent" :x1="sx(line.a.x)" :y1="sy(line.a.y)" :x2="sx(line.b.x)" :y2="sy(line.b.y)" class="cw-line cw-line-tangent" pathLength="1" />
            <line v-else data-testid="curve-real-chord" :x1="sx(line.a.x)" :y1="sy(line.a.y)" :x2="sx(line.b.x)" :y2="sy(line.b.y)" class="cw-line" pathLength="1" />
            <g data-testid="curve-real-reflect" class="cw-reflect-g">
              <line :x1="sx(sample.rPrime.x)" :y1="sy(sample.rPrime.y)" :x2="sx(sample.r.x)" :y2="sy(sample.r.y)" class="cw-reflect" pathLength="1" />
              <polygon :points="arrow(sx(sample.r.x), sy(sample.r.y), sy(sample.r.y) > sy(sample.rPrime.y) ? 1 : -1)" class="cw-reflect-head" />
            </g>
            <circle data-testid="curve-real-point-q" :data-x="String(sample.q.x)" :data-y="String(sample.q.y)" :cx="sx(sample.q.x)" :cy="sy(sample.q.y)" r="6" class="cw-pt cw-q" />
            <circle data-testid="curve-real-point-p" :data-x="String(sample.p.x)" :data-y="String(sample.p.y)" :cx="sx(sample.p.x)" :cy="sy(sample.p.y)" r="6" class="cw-pt cw-p" />
            <circle data-testid="curve-real-point-r-prime" :data-x="String(sample.rPrime.x)" :data-y="String(sample.rPrime.y)" :cx="sx(sample.rPrime.x)" :cy="sy(sample.rPrime.y)" r="6" class="cw-pt cw-rp" />
            <circle data-testid="curve-real-point-r" :data-x="String(sample.r.x)" :data-y="String(sample.r.y)" :cx="sx(sample.r.x)" :cy="sy(sample.r.y)" r="7" class="cw-pt cw-r" />
            <text :x="sx(sample.p.x) - 14" :y="sy(sample.p.y) - 10" class="cw-tag cw-p-t">P</text>
            <text v-if="sample.kind === 'chord'" :x="sx(sample.q.x) + 9" :y="sy(sample.q.y) - 10" class="cw-tag cw-q-t">Q</text>
            <text :x="sx(sample.rPrime.x) + 9" :y="sy(sample.rPrime.y) - 10" class="cw-tag cw-rp-t">R'</text>
            <text :x="sx(sample.r.x) + 10" :y="sy(sample.r.y) + 4" class="cw-tag cw-r-t">R</text>
          </g>
        </svg>
        <div class="cw-real-side">
          <p class="cw-cap" aria-live="polite" data-testid="curve-real-caption">{{ caption }}</p>
          <dl v-if="sample" class="cw-coords">
            <dt class="cw-p-t">P</dt><dd>({{ dec3(sample.p.x) }}, {{ dec3(sample.p.y) }})</dd>
            <template v-if="sample.kind === 'chord'"><dt class="cw-q-t">Q</dt><dd>({{ dec3(sample.q.x) }}, {{ dec3(sample.q.y) }})</dd></template>
            <dt class="cw-rp-t">R'</dt><dd>({{ dec3(sample.rPrime.x) }}, {{ dec3(sample.rPrime.y) }})</dd>
            <dt class="cw-r-t">R</dt><dd>({{ dec3(sample.r.x) }}, {{ dec3(sample.r.y) }})</dd>
          </dl>
          <button type="button" class="cw-pick" data-testid="curve-real-replay" @click="play++">Draw it again</button>
          <p class="muted cw-small">A vertical line meets the curve at no third point. That missing point is O, the point at infinity: P + (−P) = O.</p>
        </div>
      </div>
    </template>
  </section>
</template>
