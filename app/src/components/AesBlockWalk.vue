<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import gloss from '../walk-gloss.json'
import { byteAt, cellIndex, cellText, keyWordsOf, letterOf, stopsOf, textOf, type AesBlockReply, type AesTables, type Stop } from '../walk'
import FieldPanel from './FieldPanel.vue'
import KeySchedulePanel from './KeySchedulePanel.vue'
import SboxView from './SboxView.vue'

// Chapter 1 of the AES walk: one block, step by step (design sections 2.2, 2.2a, 2.2b, 2.2c, 2.3). Every byte is from the engine's reply.
const props = defineProps<{ block: AesBlockReply; tables: AesTables }>()
const nk = computed(() => keyWordsOf(props.tables, props.block.keyBits))
const stops = computed(() => stopsOf(props.block, nk.value))
const at = ref(0)
watch(() => props.block, () => { at.value = 0 })
const stop = computed<Stop>(() => stops.value[Math.min(at.value, stops.value.length - 1)])
const isEnd = computed(() => at.value === stops.value.length - 1)
const ROWS = [0, 1, 2, 3]

// A clicked cell feeds the S-box view and the field panel. Each new stop starts on byte 0, so a panel never shows a byte from another stop.
const picked = ref(0)
watch(at, () => { picked.value = 0 })
function pick(r: number, c: number) { picked.value = cellIndex(r, c) }

const stepKind = computed(() => (stop.value.kind === 'step' ? stop.value.step.kind : ''))
const isSub = computed(() => stepKind.value === 'SubBytes' || stepKind.value === 'InvSubBytes')
const isMix = computed(() => stepKind.value === 'MixColumns' || stepKind.value === 'InvMixColumns')
/** On a substitution step: the byte that went in, from the stop before, at the picked cell. */
const byteIn = computed(() => (stop.value.kind === 'step' ? byteAt(stop.value.prev, picked.value) : ''))
const mixed = computed(() => (stop.value.kind === 'step' ? stop.value.step.terms?.[picked.value] ?? null : null))

// The label names the cipher step by its FIPS 197 name. The first view, the key schedule, and the decrypt Start view are stops, not steps, so they carry other words.
const kind = computed(() => {
  const s = stop.value
  if (s.kind === 'fill') return 'Your block'
  if (s.kind === 'keys') return gloss.keys.title
  if (s.kind === 'decrypt-start') return 'Decrypt starts'
  return s.step.kind
})
const words = computed(() => {
  const s = stop.value
  if (s.kind === 'fill') return gloss.fill
  if (s.kind === 'keys') return ''
  if (s.kind === 'decrypt-start') return gloss.decryptStart
  const line = (gloss.steps as Record<string, string>)[s.step.kind] ?? ''
  return line.replace('{round}', String(s.step.round))
})
const where = computed(() => {
  const s = stop.value
  if (s.kind === 'fill') return `${s.filled} of 16 bytes`
  if (s.kind === 'keys') return s.built === 0 ? `The key: ${nk.value} words` : `w${nk.value + s.built - 1}, word ${s.built} of ${props.block.keyWords.length - nk.value} to build`
  if (s.kind === 'decrypt-start') return 'Between encrypt and decrypt'
  return `${s.run === 'encrypt' ? 'Encrypt' : 'Decrypt'}, round ${s.step.round} of ${props.block.rounds}`
})
const letter = (r: number, c: number) => { const t = cellText(stop.value, r, c); return t ? letterOf(t) : '' }
const canPick = computed(() => isSub.value || isMix.value)
function next() { if (!isEnd.value) at.value++ }
function back() { if (at.value > 0) at.value-- }
</script>

<template>
  <div class="aes-walk" data-testid="aes-walk-block">
    <div class="aw-head">
      <span class="aw-kind" data-testid="aes-walk-step-kind">{{ kind }}</span>
      <span class="muted">{{ where }}</span>
      <v-spacer />
      <div class="aw-controls">
        <span class="muted">Stop {{ at + 1 }} of {{ stops.length }}</span>
        <v-btn :disabled="at === 0" data-testid="aes-walk-back" @click="back">Back</v-btn>
        <v-btn color="primary" :disabled="isEnd" data-testid="aes-walk-next" @click="next">Next</v-btn>
      </div>
    </div>
    <div class="aw-bench">
      <!-- The key schedule stops show the key, not the block, so the block grid steps aside there. -->
      <div v-if="stop.kind !== 'keys'" class="aw-grid" role="grid" aria-label="The state, 4 rows by 4 columns">
        <template v-for="r in ROWS" :key="r">
          <span
            v-for="c in ROWS" :key="c" class="aw-cell" role="gridcell" :data-testid="`aes-walk-cell-${r}-${c}`"
            :class="{ 'aw-picked': canPick && picked === cellIndex(r, c) }"
            :tabindex="canPick ? 0 : undefined"
            :data-letter="letter(r, c) || undefined" data-hex-byte
            @click="pick(r, c)" @keydown.enter.prevent="pick(r, c)" @keydown.space.prevent="pick(r, c)"
          >{{ cellText(stop, r, c) }}</span>
        </template>
      </div>
      <div class="aw-right">
        <div class="aw-words">
          <p v-if="stop.kind === 'fill'" data-testid="aes-walk-first-view">{{ words }}</p>
          <p v-else-if="words">{{ words }}</p>
          <p v-if="isEnd" class="aw-readable-line">{{ gloss.end }} <span class="aw-readable" data-testid="aes-walk-readable">{{ textOf(stop.state) }}</span></p>
        </div>
        <KeySchedulePanel v-if="stop.kind === 'keys'" :block="block" :tables="tables" :nk="nk" :built="stop.built" />
        <SboxView v-else-if="isSub" :table="stepKind === 'SubBytes' ? tables.sbox : tables.inverseSbox" :byte="byteIn" :inverse="stepKind === 'InvSubBytes'" />
        <FieldPanel v-else-if="isMix" :mixed="mixed" :cell="picked" />
      </div>
    </div>
  </div>
</template>
