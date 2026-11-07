<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import gloss from '../walk-gloss.json'
import { cellText, letterOf, stopsOf, textOf, type AesBlockReply, type Stop } from '../walk'

// Chapter 1 of the AES walk: one block, step by step (design sections 2.2 and 2.2a). Every byte is from the engine's reply.
const props = defineProps<{ block: AesBlockReply }>()
const stops = computed(() => stopsOf(props.block))
const at = ref(0)
watch(() => props.block, () => { at.value = 0 })
const stop = computed<Stop>(() => stops.value[Math.min(at.value, stops.value.length - 1)])
const isEnd = computed(() => at.value === stops.value.length - 1)
const ROWS = [0, 1, 2, 3]

// The label names the cipher step by its FIPS 197 name. The first view and the decrypt Start view are stops, not steps, so they carry other words.
const kind = computed(() => {
  const s = stop.value
  if (s.kind === 'fill') return 'Your block'
  if (s.kind === 'decrypt-start') return 'Decrypt starts'
  return s.step.kind
})
const words = computed(() => {
  const s = stop.value
  if (s.kind === 'fill') return gloss.fill
  if (s.kind === 'decrypt-start') return gloss.decryptStart
  const line = (gloss.steps as Record<string, string>)[s.step.kind] ?? ''
  return line.replace('{round}', String(s.step.round))
})
const where = computed(() => {
  const s = stop.value
  if (s.kind === 'fill') return `${s.filled} of 16 bytes`
  if (s.kind === 'decrypt-start') return 'Between encrypt and decrypt'
  return `${s.run === 'encrypt' ? 'Encrypt' : 'Decrypt'}, round ${s.step.round} of ${props.block.rounds}`
})
const letter = (r: number, c: number) => { const t = cellText(stop.value, r, c); return t ? letterOf(t) : '' }
function next() { if (!isEnd.value) at.value++ }
function back() { if (at.value > 0) at.value-- }
</script>

<template>
  <div class="aes-walk" data-testid="aes-walk-block">
    <div class="aw-head">
      <span class="aw-kind" data-testid="aes-walk-step-kind">{{ kind }}</span>
      <span class="muted">{{ where }}</span>
    </div>
    <div class="aw-bench">
      <div class="aw-grid" role="grid" aria-label="The state, 4 rows by 4 columns">
        <template v-for="r in ROWS" :key="r">
          <span
            v-for="c in ROWS" :key="c" class="aw-cell" role="gridcell" :data-testid="`aes-walk-cell-${r}-${c}`"
            :data-letter="letter(r, c) || undefined" data-hex-byte
          >{{ cellText(stop, r, c) }}</span>
        </template>
      </div>
      <div class="aw-words">
        <p v-if="stop.kind === 'fill'" data-testid="aes-walk-first-view">{{ words }}</p>
        <p v-else>{{ words }}</p>
        <p v-if="isEnd" class="aw-readable-line">{{ gloss.end }} <span class="aw-readable" data-testid="aes-walk-readable">{{ textOf(stop.state) }}</span></p>
      </div>
    </div>
    <div class="aw-controls">
      <v-btn :disabled="at === 0" data-testid="aes-walk-back" @click="back">Back</v-btn>
      <v-btn color="primary" :disabled="isEnd" data-testid="aes-walk-next" @click="next">Next</v-btn>
      <span class="muted">Stop {{ at + 1 }} of {{ stops.length }}</span>
    </div>
  </div>
</template>
