<script setup lang="ts">
import { computed, nextTick, provide, ref, watch } from 'vue'
import gloss from '../walk-gloss.json'
import { SPEEDS, useWalkTimeline } from '../useWalkTimeline'
import { byteAt, cellIndex, cellText, keyWordsOf, letterOf, playGroupOf, stopsOf, textOf, type AesBlockReply, type AesTables, type Stop } from '../walk'
import { clearMarks, shiftOf, startMotion } from '../walkMotion'
import FieldPanel from './FieldPanel.vue'
import KeySchedulePanel from './KeySchedulePanel.vue'
import MixPanel from './MixPanel.vue'
import SboxView from './SboxView.vue'

// Chapter 1 of the AES walk: one block, step by step (design sections 2.2, 2.2a, 2.2b, 2.2c, 2.3, 2.8). Every byte is from the engine's reply.
const props = defineProps<{ block: AesBlockReply; tables: AesTables }>()
const nk = computed(() => keyWordsOf(props.tables, props.block.keyBits))
const stops = computed(() => stopsOf(props.block, nk.value))
const at = ref(0)
const stop = computed<Stop>(() => stops.value[Math.min(at.value, stops.value.length - 1)])
const isEnd = computed(() => at.value === stops.value.length - 1)
const ROWS = [0, 1, 2, 3]

// The one clock: every motion and every wait goes through it (design 2.2a). The root element holds all of them.
const tl = useWalkTimeline()
// The key schedule panel plays each word's build on this same clock, so Pause, Next and Back reach it too.
provide('aesWalkTimeline', tl)
const root = ref<HTMLElement | null>(null)
watch(() => props.block, () => { stopTimeline(); at.value = 0 })

// A clicked cell feeds the S-box view and the field panel. Each new stop starts on byte 0, so a panel never shows a byte from another stop.
const picked = ref(0)
watch(at, () => { picked.value = 0 })
/** A tap that changes the view ends the current motion first, and Play stops (design 2.2a). */
function pick(r: number, c: number) {
  if (tl.running.value) tl.finishNow()
  picked.value = cellIndex(r, c)
}

function stopTimeline() {
  tl.stopAll()
  if (root.value) clearMarks(root.value)
}

/** Moves one stop on, and starts that stop's motion once the end frame is on screen. */
async function advance() {
  if (isEnd.value) return
  tl.clearFinished()
  at.value++
  await nextTick()
  if (root.value) startMotion({ root: root.value, to: stop.value, tables: props.tables, nk: nk.value, animate: tl.animate })
}

/** Next. During a motion it only jumps that motion to its end frame. While paused, the motion ends and Next moves on (design 2.2a). */
function next() {
  if (tl.paused.value) { stopTimeline(); void advance(); return }
  if (tl.moving()) { tl.finishNow(); return }
  tl.playing.value = false
  void advance()
}

/** Start over, on the key schedule: back to the key alone, with no motion. */
function startOver() {
  stopTimeline()
  at.value = stops.value.findIndex(s => s.kind === 'keys')
}

/** Back lands on the stop before, with no motion and no mark left behind. */
function back() {
  stopTimeline()
  if (at.value > 0) at.value--
}

/** Play runs to the end of the current part and stops: one round, one key grid, or the first view (design 2.8). */
async function play() {
  tl.playing.value = true
  do {
    await advance()
    await tl.settle()
    // A stop during the motion (Next, Back, Show keys off) ends the loop here, before it waits again (Jared on #255).
    if (!tl.playing.value) return
    await tl.delay(tl.reduced() ? 650 : 280)
    if (!tl.playing.value) return
  } while (!isEnd.value && playGroupOf(stop.value, nk.value) === playGroupOf(stops.value[at.value + 1], nk.value))
  tl.playing.value = false
}

function playButton() {
  if (tl.paused.value) tl.resume()
  else if (tl.running.value) tl.pause()
  else void play()
}

/** On ShiftRows, the bytes that wrapped round the edge keep the highlight on the end frame: a staircase (design 2.2a). */
function wrapped(r: number, c: number): boolean {
  if (stepKind.value !== 'ShiftRows' && stepKind.value !== 'InvShiftRows') return false
  const inverse = stepKind.value === 'InvShiftRows'
  return shiftOf(inverse ? props.tables.inverseShiftRows : props.tables.shiftRows, cellIndex(r, c), inverse).wrapped
}

const stepKind = computed(() => (stop.value.kind === 'step' ? stop.value.step.kind : ''))
const isSub = computed(() => stepKind.value === 'SubBytes' || stepKind.value === 'InvSubBytes')
const isMix = computed(() => stepKind.value === 'MixColumns' || stepKind.value === 'InvMixColumns')
// AddRoundKey (Steve, the mock's block tab): the round key grid beside the state, titled with its round, and the bit lines of the picked byte.
const isArk = computed(() => stepKind.value === 'AddRoundKey' && !!(stop.value.kind === 'step' && stop.value.step.roundKey))
const roundKey = computed(() => (stop.value.kind === 'step' ? stop.value.step.roundKey ?? '' : ''))
const arkBits = computed(() => {
  if (!isArk.value || stop.value.kind !== 'step') return null
  const i = picked.value
  return { state: byteAt(stop.value.prev, i), key: byteAt(roundKey.value, i), result: byteAt(stop.value.state, i) }
})
const nib = (h: string) => { const b = parseInt(h, 16).toString(2).padStart(8, '0'); return `${b.slice(0, 4)} ${b.slice(4)}` }
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
/** The character a cell shows, as the mock's block does: "sp" for a space, the character, or a dot for a byte that is not printable. */
function charOf(r: number, c: number): string {
  const t = cellText(stop.value, r, c)
  if (!t) return ''
  if (t === '20') return 'sp'
  return letterOf(t) || '·'
}
const canPick = computed(() => isSub.value || isMix.value || isArk.value)
</script>

<template>
  <div ref="root" class="aes-walk" data-testid="aes-walk-block">
    <div class="aw-head">
      <span class="aw-kind" data-testid="aes-walk-step-kind">{{ kind }}</span>
      <span class="muted">{{ where }}</span>
      <v-spacer />
      <div class="aw-controls">
        <span class="muted">Stop {{ at + 1 }} of {{ stops.length }}</span>
        <v-btn-toggle v-model="tl.speed.value" mandatory density="compact" variant="outlined" divided data-testid="aes-walk-speed" aria-label="Speed">
          <v-btn v-for="s in SPEEDS" :key="s" :value="s" size="small" :ripple="false">{{ s }}</v-btn>
        </v-btn-toggle>
        <v-btn :disabled="at === 0" :ripple="false" data-testid="aes-walk-back" @click="back">Back</v-btn>
        <v-btn
          :disabled="isEnd && !tl.running.value" :ripple="false" variant="tonal" data-testid="aes-walk-play"
          :prepend-icon="tl.buttonWord.value === 'Pause' ? 'mdi-pause' : 'mdi-play'" @click="playButton"
        >{{ tl.buttonWord.value }}</v-btn>
        <v-btn color="primary" :disabled="isEnd" :ripple="false" data-testid="aes-walk-next" @click="next">{{ stop.kind === 'keys' && stops[at + 1]?.kind === 'keys' ? 'Next word' : 'Next' }}</v-btn>
      </div>
    </div>
    <div class="aw-bench">
      <!-- The key schedule stops show the key, not the block, so the block grid steps aside there. -->
      <div v-if="stop.kind !== 'keys'" class="aw-grid" role="grid" aria-label="The state, 4 rows by 4 columns">
        <!-- Each row wrapper is display: contents, so the 4 by 4 CSS grid still places the cells, and assistive tech still reads rows. -->
        <div v-for="r in ROWS" :key="r" class="aw-row" role="row">
          <span
            v-for="c in ROWS" :key="c" class="aw-cell" role="gridcell" :data-testid="`aes-walk-cell-${r}-${c}`"
            :class="{ 'aw-picked': canPick && picked === cellIndex(r, c), 'aw-wrap': wrapped(r, c) }"
            :tabindex="canPick ? 0 : undefined"
            :data-letter="letter(r, c) || undefined" data-hex-byte :data-hex="cellText(stop, r, c)"
            @click="pick(r, c)" @keydown.enter.prevent="pick(r, c)" @keydown.space.prevent="pick(r, c)"
          ><!-- The hex comes first, so a reader of the cell's text gets the byte first. The index and the character sit in the corners. -->{{ cellText(stop, r, c) }}<span class="aw-idx" :data-testid="`aes-walk-cell-${r}-${c}-index`" aria-hidden="true">{{ cellIndex(r, c) }}</span><span class="aw-ch" :data-testid="`aes-walk-cell-${r}-${c}-char`" aria-hidden="true">{{ charOf(r, c) }}</span></span>
        </div>
      </div>
      <!-- The round key this AddRoundKey uses, beside the state. On a motion its bytes move to meet the state bytes (walkMotion.ts). -->
      <div v-if="isArk" class="aw-slot" data-testid="aes-walk-round-key-grid">
        <h3 class="aw-slot-title" data-testid="aes-walk-round-key-label">Round key {{ stop.kind === 'step' ? stop.step.round : '' }}</h3>
        <div class="aw-grid aw-key-grid" role="grid" :aria-label="`Round key ${stop.kind === 'step' ? stop.step.round : ''}, 4 rows by 4 columns`">
          <div v-for="r in ROWS" :key="r" class="aw-row" role="row">
            <span v-for="c in ROWS" :key="c" class="aw-cell aw-key-cell" role="gridcell" :data-testid="`aes-walk-round-key-cell-${r}-${c}`" :data-hex="byteAt(roundKey, cellIndex(r, c))">{{ byteAt(roundKey, cellIndex(r, c)) }}<span class="aw-idx" aria-hidden="true">{{ cellIndex(r, c) }}</span></span>
          </div>
        </div>
      </div>
      <div class="aw-right">
        <div class="aw-words">
          <p v-if="stop.kind === 'fill'" data-testid="aes-walk-first-view">{{ words }}</p>
          <p v-else-if="words">{{ words }}</p>
          <p v-if="isEnd" class="aw-readable-line">{{ gloss.end }} <span class="aw-readable" data-testid="aes-walk-readable">{{ textOf(stop.state) }}</span></p>
        </div>
        <KeySchedulePanel v-if="stop.kind === 'keys'" :block="block" :tables="tables" :nk="nk" :built="stop.built" @start-over="startOver" />
        <SboxView v-else-if="isSub" :table="stepKind === 'SubBytes' ? tables.sbox : tables.inverseSbox" :byte="byteIn" :inverse="stepKind === 'InvSubBytes'" />
        <FieldPanel v-else-if="isMix" :mixed="mixed" :cell="picked" />
        <div v-else-if="arkBits" class="aw-bits" data-testid="aes-walk-ark-bits">
          <p class="muted">Byte {{ picked }}: the state byte XOR the key byte. Click a byte in the state to pick another.</p>
          <pre><span class="aw-bits-state" data-testid="aes-walk-bits-state">{{ '    ' + nib(arkBits.state) }}  {{ arkBits.state }}</span>
<span class="aw-bits-key" data-testid="aes-walk-bits-key">{{ 'XOR ' + nib(arkBits.key) }}  {{ arkBits.key }}</span>
<span class="aw-bits-result" data-testid="aes-walk-bits-result">{{ '  = ' + nib(arkBits.result) }}  {{ arkBits.result }}</span></pre>
        </div>
      </div>
    </div>
    <MixPanel v-if="isMix && stop.kind === 'step' && stop.step.terms" :step="stop.step" :prev="stop.prev" :picked-col="Math.floor(picked / 4)" />
  </div>
</template>
