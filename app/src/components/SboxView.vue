<script setup lang="ts">
import { computed } from 'vue'
import gloss from '../walk-gloss.json'
import { byteAt } from '../walk'

// The S-box view (design section 2.3). The table is the engine's own, from the tables route. A lookup is position arithmetic:
// the byte's first digit picks the row and the second picks the column. The view computes no byte.
const props = defineProps<{ table: string; byte: string; inverse: boolean }>()
const DIGITS = '0123456789abcdef'.split('')

const row = computed(() => props.byte.charAt(0).toLowerCase())
const col = computed(() => props.byte.charAt(1).toLowerCase())
const at = (x: string, y: string) => byteAt(props.table, 16 * parseInt(x, 16) + parseInt(y, 16))
const value = computed(() => (props.byte.length === 2 ? at(row.value, col.value) : ''))
</script>

<template>
  <div class="aw-sbox" data-testid="aes-walk-sbox">
    <p v-if="byte.length === 2" class="aw-sbox-lookup">
      <span class="aw-sbox-in">{{ byte }}</span>: row <b data-testid="aes-walk-sbox-row">{{ row }}</b>, column <b data-testid="aes-walk-sbox-col">{{ col }}</b>
      gives <b class="aw-sbox-out" data-testid="aes-walk-sbox-value">{{ value }}</b>
    </p>
    <table class="aw-sbox-table" :aria-label="inverse ? 'The inverse S-box' : 'The S-box'">
      <thead>
        <tr><th />
          <th v-for="y in DIGITS" :key="y" :class="{ 'aw-sbox-hit': y === col }" scope="col">{{ y }}</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="x in DIGITS" :key="x">
          <th :class="{ 'aw-sbox-hit': x === row }" scope="row">{{ x }}</th>
          <td
            v-for="y in DIGITS" :key="y" :data-testid="`aes-walk-sbox-cell-${x}-${y}`"
            :class="{ 'aw-sbox-line': x === row || y === col, 'aw-sbox-cross': x === row && y === col }"
          >{{ at(x, y) }}</td>
        </tr>
      </tbody>
    </table>
    <div class="aw-sbox-words">
      <p class="muted">{{ gloss.sbox.pick }}</p>
      <p class="muted">{{ gloss.sbox.facts }}</p>
      <p v-if="inverse">{{ gloss.sbox.inverse }}</p>
    </div>
  </div>
</template>
