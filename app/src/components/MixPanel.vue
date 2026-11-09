<script setup lang="ts">
import { computed, inject, nextTick, reactive, ref, watch } from 'vue'
import type { useWalkTimeline } from '../useWalkTimeline'
import { byteAt, type AesStepRow, type AesTerm } from '../walk'

// "How MixColumns multiplies", from the mock's block tab (Steve, 2026-11-08): the fixed matrix times one state column gives the state
// after. Each column has 20 positions: for each of its 4 rows, 4 products and then their XOR. Every factor, product and sum is from the
// engine's terms (R5): the panel shows them and computes nothing. Play runs on the walk's one clock.
const props = defineProps<{ step: AesStepRow; prev: string; pickedCol: number }>()
const tl = inject<ReturnType<typeof useWalkTimeline> | null>('aesWalkTimeline', null)
const ROWS = [0, 1, 2, 3]

const v = reactive({ col: props.pickedCol, pos: 0, all: false, done: new Set<number>() })
const playing = ref(false)
let token = 0
const root = ref<HTMLElement | null>(null)

function reset(col: number) { stop(); v.col = col; v.pos = 0; v.all = false; v.done = new Set() }
watch(() => props.step, () => reset(props.pickedCol))
watch(() => props.pickedCol, c => { if (c !== v.col) { stop(); v.col = c; v.pos = 0; v.all = false; void flyColumn() } })

const row = computed(() => Math.floor(v.pos / 5))
const k = computed(() => v.pos % 5)
const termAt = (c: number, r: number) => props.step.terms?.[r + 4 * c] ?? null
/** The fixed matrix: the factor row r gives byte k, read from the engine's products of column 0. */
const factor = (r: number, kk: number) => termAt(0, r)?.parts[kk]?.factor ?? 0
const before = (c: number, r: number) => byteAt(props.prev, r + 4 * c)
const after = (c: number, r: number) => byteAt(props.step.state, r + 4 * c)
function filled(c: number, r: number): boolean {
  if (v.all || v.done.has(c)) return true
  return c === v.col && (r < row.value || (r === row.value && k.value === 4))
}
const active = computed(() => !v.all)
const isPair = (r: number, kk: number) => active.value && r === row.value && kk === k.value
const term = computed<AesTerm | null>(() => (k.value < 4 ? termAt(v.col, row.value)?.parts[k.value] ?? null : null))
const total = computed(() => termAt(v.col, row.value)?.result ?? '')

/** The field multiply in words, from the factor and the engine's `reduced` flag. A shifted or doubled value shows when the engine sends one. */
function how(t: AesTerm & { shifted?: string | null; doubled?: string | null }): string {
  if (t.factor === 1) return 'Times 1 leaves the byte as it is.'
  const shift = t.shifted ? `Field multiply by 2: shift the bits left by one, to get ${t.shifted}.` : 'Field multiply by 2: shift the bits left by one.'
  const fit = t.reduced ? ' That is too big for a byte, so it is reduced by 11b.' : ' It fits in a byte.'
  if (t.factor === 2) return shift + fit
  const xorLine = t.doubled ? ` ${t.doubled} XOR ${t.input} = ${t.result}.` : ''
  return `${shift}${fit} Times 3 is times 2, then XOR the byte itself.${xorLine}`
}
const caption = computed(() => {
  if (v.all) return { top: 'All 4 columns are done.', sub: 'The result is the state after MixColumns.' }
  if (term.value) return { top: `${term.value.factor} × ${term.value.input} = ${term.value.result}`, sub: `Row ${row.value} of the matrix, byte ${k.value} of column ${v.col}. ${how(term.value)}` }
  return { top: `Output byte ${row.value} = ${total.value}`, sub: `Add the 4 results with XOR. The answer goes in row ${row.value}, column ${v.col}.` }
})
const products = computed(() => termAt(v.col, row.value)?.parts ?? [])

const nib = (h: string) => { const b = parseInt(h, 16).toString(2).padStart(8, '0'); return `${b.slice(0, 4)} ${b.slice(4)}` }

// ---- Moving through a column. Past the end of a column, the next column starts.
function stepBy(d: number) {
  v.all = false
  let next = v.pos + d
  if (next > 19) {
    v.done = new Set([...v.done, v.col])
    if (v.col < 3) { v.col++; next = 0; void flyColumn() } else { next = 19; v.all = true }
  }
  if (next < 0) {
    if (v.col > 0) { const d2 = new Set(v.done); v.col--; d2.delete(v.col); v.done = d2; next = 19; void flyColumn() } else next = 0
  }
  v.pos = next
  if (k.value === 4) void pulse()
}
function stop() { playing.value = false; token++ }
function next() { stop(); stepBy(1) }
function back() { stop(); stepBy(-1) }
function fillAll() { stop(); v.done = new Set(ROWS); v.all = true }
function pickCol(c: number) { stop(); v.col = c; v.pos = 0; v.all = false; void flyColumn() }

/** Play this column: one position at a time, to the column's last sum. Pause stops it where it is. */
async function play() {
  if (playing.value) { stop(); return }
  if (v.all) { v.all = false; v.done = new Set(); v.col = 0; v.pos = 0; void flyColumn() }
  const run = ++token
  playing.value = true
  while (run === token && v.pos < 19) {
    if (tl) await tl.delay(v.pos % 5 === 4 ? 1100 : 1500)
    else await new Promise(r => setTimeout(r, 600))
    if (run !== token) return
    stepBy(1)
  }
  if (run === token) { v.done = new Set([...v.done, v.col]); playing.value = false }
}

/** The column's 4 bytes fly from the state up to the strip above the matrix, as in the mock. */
async function flyColumn() {
  await nextTick()
  if (!tl || !root.value) return
  for (const r of ROWS) {
    const to = root.value.querySelector<HTMLElement>(`[data-testid="aes-walk-mix-strip-${r}"]`)
    const from = root.value.querySelector<HTMLElement>(`[data-testid="aes-walk-mix-state-cell-${r}-${v.col}"]`)
    if (!to || !from) continue
    const a = from.getBoundingClientRect(), b = to.getBoundingClientRect()
    tl.animate(to, [{ transform: `translate(${a.left - b.left}px, ${a.top - b.top}px)` }, { transform: 'none' }], { duration: 560, delay: r * 90, easing: 'ease-in-out', fill: 'backwards' })
  }
}
async function pulse() {
  await nextTick()
  const el = root.value?.querySelector(`[data-testid="aes-walk-mix-after-cell-${row.value}-${v.col}"]`)
  if (el && tl) tl.animate(el, [{ transform: 'scale(1.25)' }, { transform: 'none' }], { duration: 320, easing: 'ease-out', fill: 'none' })
}
</script>

<template>
  <section ref="root" class="aw-mix" data-testid="aes-walk-mix" aria-labelledby="aw-mix-title">
    <h3 id="aw-mix-title" class="aw-mix-title">How MixColumns multiplies</h3>
    <p class="muted">Each output byte comes from one row of the fixed matrix and one column of the state. Pair them up, multiply each pair in the field, and add the results with XOR.</p>
    <div class="aw-mix-controls">
      <div class="aw-mix-tabs" role="group" aria-label="Column">
        <button v-for="c in ROWS" :key="c" type="button" class="aw-mix-tab" :aria-pressed="!v.all && v.col === c" :data-testid="`aes-walk-mix-col-${c}`" @click="pickCol(c)">Column {{ c }}</button>
      </div>
      <v-btn size="small" :disabled="v.col === 0 && v.pos === 0 && !v.all" data-testid="aes-walk-mix-back" @click="back">Back</v-btn>
      <v-btn size="small" color="primary" variant="tonal" data-testid="aes-walk-mix-play" @click="play">{{ playing ? 'Pause' : 'Play this column' }}</v-btn>
      <v-btn size="small" :disabled="v.all" data-testid="aes-walk-mix-next" @click="next">Next</v-btn>
      <v-btn size="small" variant="text" data-testid="aes-walk-mix-fill" @click="fillAll">Fill all</v-btn>
    </div>
    <div class="aw-mix-bench">
      <div class="aw-mix-block">
        <span class="aw-mix-label">The fixed matrix</span>
        <div class="aw-mix-strip" :style="{ visibility: v.all ? 'hidden' : 'visible' }">
          <span v-for="r in ROWS" :key="r" class="aw-mix-cell aw-mix-chip" :data-pair="isPair(row, r) ? 'true' : undefined" :data-testid="`aes-walk-mix-strip-${r}`">{{ before(v.col, r) }}</span>
        </div>
        <div class="aw-mix-bracket">
          <div class="aw-mix-grid">
            <template v-for="r in ROWS" :key="r">
              <span
                v-for="kk in ROWS" :key="kk" class="aw-mix-cell aw-mix-factor" :style="{ gridRow: r + 1, gridColumn: kk + 1 }"
                :data-row="active && r === row ? 'true' : undefined" :data-pair="isPair(r, kk) ? 'true' : undefined"
                :data-testid="`aes-walk-mix-matrix-cell-${r}-${kk}`"
              >{{ factor(r, kk) }}</span>
            </template>
          </div>
        </div>
      </div>
      <span class="aw-mix-op" aria-hidden="true">×</span>
      <div class="aw-mix-block">
        <span class="aw-mix-label">State before</span>
        <div class="aw-mix-spacer" />
        <div class="aw-mix-bracket">
          <div class="aw-mix-grid">
            <template v-for="r in ROWS" :key="r">
              <span
                v-for="c in ROWS" :key="c" class="aw-mix-cell" :style="{ gridRow: r + 1, gridColumn: c + 1 }"
                :data-col="active && c === v.col ? 'true' : undefined" :data-pair="active && c === v.col && r === k ? 'true' : undefined"
                :data-hex="before(c, r)" :data-testid="`aes-walk-mix-state-cell-${r}-${c}`"
              >{{ before(c, r) }}</span>
            </template>
          </div>
        </div>
      </div>
      <span class="aw-mix-op" aria-hidden="true">=</span>
      <div class="aw-mix-block">
        <span class="aw-mix-label">State after</span>
        <div class="aw-mix-spacer" />
        <div class="aw-mix-bracket">
          <div class="aw-mix-grid">
            <template v-for="r in ROWS" :key="r">
              <span
                v-for="c in ROWS" :key="c" class="aw-mix-cell" :class="{ 'aw-mix-empty': !filled(c, r) }" :style="{ gridRow: r + 1, gridColumn: c + 1 }"
                :data-new="active && c === v.col && r === row && k === 4 ? 'true' : undefined"
                :data-hex="filled(c, r) ? after(c, r) : ''" :data-testid="`aes-walk-mix-after-cell-${r}-${c}`"
              >{{ filled(c, r) ? after(c, r) : '' }}</span>
            </template>
          </div>
        </div>
      </div>
    </div>
    <div class="aw-mix-cap" data-testid="aes-walk-mix-caption" aria-live="polite"><b>{{ caption.top }}</b><span>{{ caption.sub }}</span></div>
    <!-- The bit lines: a product's byte and result, or the XOR of the 4 products, each as 8 bits. -->
    <pre v-if="!v.all && term" class="aw-mix-bits" data-testid="aes-walk-mix-bits"><span class="aw-bits-state">{{ `${term.input}`.padEnd(6) }}{{ nib(term.input) }}</span>
<span class="aw-bits-result">{{ `×${term.factor} = ${term.result}`.padEnd(10) }}{{ nib(term.result) }}</span></pre>
    <pre v-else-if="!v.all" class="aw-mix-bits" data-testid="aes-walk-mix-bits"><template v-for="(p, j) in products" :key="j"><span :class="j === 0 ? 'aw-bits-state' : 'aw-bits-key'">{{ (j === 0 ? '    ' : 'XOR ') + nib(p.result) }}  {{ p.result }}</span>
</template><span class="aw-bits-result">{{ '  = ' + nib(total) }}  {{ total }}</span></pre>
    <div v-if="!v.all" class="aw-mix-run" data-testid="aes-walk-mix-run">
      <template v-for="(p, j) in products" :key="j"><span v-if="j > 0"> xor </span><span class="aw-mix-kb" :class="{ 'aw-mix-pick': j === k }">{{ j <= k ? p.result : '--' }}</span></template>
      = <span class="aw-mix-kb" :class="{ 'aw-mix-pick': k === 4 }">{{ k === 4 ? total : '--' }}</span>
    </div>
  </section>
</template>
