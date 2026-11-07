<script setup lang="ts">
import gloss from '../walk-gloss.json'
import type { AesMixedByte } from '../walk'

// The finite field (design section 2.2c): the 5 definition lines, then one real multiply from the step.
// The engine returns each product and the XOR of the 4. The panel prints them and computes nothing.
// The definition lines live in walk-gloss.json under "definition"; acceptance/checks reads them from there and from this file.
defineProps<{ mixed: AesMixedByte | null; cell: number | null }>()
</script>

<template>
  <div class="aw-field" data-testid="aes-walk-field-panel">
    <ol class="aw-field-def">
      <li v-for="(line, n) in gloss.definition" :key="n">{{ line }}</li>
    </ol>
    <div v-if="mixed" class="aw-field-mul">
      <p class="muted">Byte {{ cell }} after this step is the XOR of 4 products:</p>
      <div
        v-for="(t, j) in mixed.parts" :key="j" class="aw-field-term" :data-testid="`aes-walk-term-${j}`"
        :data-reduced="String(t.reduced)"
      >
        <span>{{ t.factor }} × {{ t.input }} = <b>{{ t.result }}</b></span>
        <span v-if="t.reduced" class="muted">, {{ gloss.field.reduced }}</span>
      </div>
      <p class="aw-field-sum" data-testid="aes-walk-term-result">XOR of the 4 products: <b>{{ mixed.result }}</b></p>
    </div>
    <p v-else class="muted">{{ gloss.field.pick }}</p>
  </div>
</template>
