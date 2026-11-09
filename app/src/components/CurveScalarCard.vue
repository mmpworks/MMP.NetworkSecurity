<script setup lang="ts">
import { computed, ref } from 'vue'
import { ptAttrs, ptText, type ToyCurve } from '../curveWalk'

// k·G the fast way, on the engine's rows (slice P8a; R7): double-and-add on k's bits, then the Montgomery ladder on the same k. The ladder does
// one add and one double for every bit, 1 or 0, so its timing does not give the bits away. Every point is the engine's (R5).
const props = defineProps<{ toy: ToyCurve }>()
const bits = computed(() => props.toy.doubleAndAdd.map(r => (r.isOne ? '1' : '0')).join(''))

/** The row the learner is on, in both tables. Null shows every row as done. */
const row = ref<number | null>(null)
const last = computed(() => props.toy.doubleAndAdd.length - 1)
function next() { row.value = row.value === null || row.value >= last.value ? 0 : row.value + 1 }
const state = (i: number) => (row.value === null || i < row.value ? 'done' : i === row.value ? 'now' : 'later')
</script>

<template>
  <section class="cw-card" data-testid="curve-scalar-card" aria-label="Double-and-add and the Montgomery ladder">
    <h3>4. k·G the fast way: k = {{ toy.k }}, which is {{ bits }} in binary</h3>
    <p class="muted">Hopping {{ toy.k }} times is slow for a real-size k. Double-and-add reads k's bits from the top. For each bit it doubles, and for a 1 it also adds G.</p>
    <div class="cw-controls">
      <v-btn size="small" data-testid="curve-dna-next" @click="next">Next bit</v-btn>
      <v-btn size="small" variant="text" data-testid="curve-dna-all" @click="row = null">Show all</v-btn>
    </div>
    <div class="cw-tables">
      <table class="cw-table" aria-label="Double-and-add">
        <caption>Double-and-add</caption>
        <thead><tr><th>bit</th><th>value</th><th>double</th><th>add G</th><th>point so far</th></tr></thead>
        <tbody>
          <tr v-for="(r, i) in toy.doubleAndAdd" :key="i" :data-testid="`curve-dna-row-${i}`" :class="state(i)" :aria-current="row === i ? 'true' : undefined">
            <td>{{ r.bit }}</td>
            <td><b :data-testid="`curve-dna-bit-${i}`">{{ r.isOne ? '1' : '0' }}</b></td>
            <td>{{ ptText(r.doubleStep.result) }}</td>
            <td>{{ r.addStep ? ptText(r.addStep.result) : 'skip' }}</td>
            <td><b :data-testid="`curve-dna-point-${i}`" v-bind="ptAttrs(r.after)">{{ ptText(r.after) }}</b></td>
          </tr>
        </tbody>
      </table>
      <table class="cw-table" aria-label="The Montgomery ladder">
        <caption>The Montgomery ladder</caption>
        <thead><tr><th>bit</th><th>value</th><th>add</th><th>double</th><th>R0</th><th>R1</th></tr></thead>
        <tbody>
          <tr v-for="(r, i) in toy.ladder" :key="i" :data-testid="`curve-ladder-row-${i}`" :class="state(i)" :aria-current="row === i ? 'true' : undefined">
            <td>{{ r.bit }}</td>
            <td><b>{{ r.isOne ? '1' : '0' }}</b></td>
            <td>{{ ptText(r.addStep.result) }}</td>
            <td>{{ ptText(r.doubleStep.result) }}</td>
            <td><b :data-testid="`curve-ladder-r0-${i}`" v-bind="ptAttrs(r.r0)">{{ ptText(r.r0) }}</b></td>
            <td>{{ ptText(r.r1) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="muted cw-small">Double-and-add skips the add on a 0 bit, so a listener who times it can read the bits. The ladder always does one add and one double. R0 ends on {{ toy.k }}·G = {{ ptText(toy.ladder[toy.ladder.length - 1]?.r0) }}. X25519 uses this ladder.</p>
  </section>
</template>
