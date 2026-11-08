<script setup lang="ts">
import { computed, inject, nextTick, reactive, ref, watch } from 'vue'
import gloss from '../walk-gloss.json'
import type { useWalkTimeline } from '../useWalkTimeline'
import { byteAt, expandedHex, wordTest, type AesBlockReply, type AesKeyWordRow, type AesTables } from '../walk'

// The key schedule (design section 2.2b), in the approved mock's landscape layout (Steve, 2026-11-08): the round keys on the left, and
// "How wN is made" on the right. Next onto a word plays its build: the stage rows one after another, a lifted copy of the word before
// that rotates and changes, then each byte's XOR, landing in the new word one byte at a time. Every byte is from the reply's keyWords
// rows: the app computes nothing (R5). Every beat is an animation on the walk's one clock, so Pause, Next and Back reach it.
const props = defineProps<{ block: AesBlockReply; tables: AesTables; nk: number; built: number }>()
const emit = defineEmits<{ startOver: [] }>()
const tl = inject<ReturnType<typeof useWalkTimeline> | null>('aesWalkTimeline', null)

const rows = computed(() => props.block.keyWords.slice().sort((a, b) => a.i - b.i))
const hex = computed(() => expandedHex(rows.value))
const grids = computed(() => rows.value.length / 4)
const size = computed(() => props.tables.sizes.find(s => s.keyBits === props.block.keyBits))
const ROWS = [0, 1, 2, 3]
const rowOf = (i: number): AesKeyWordRow | null => rows.value.find(r => r.i === i) ?? null
const bytes = (h: string | null) => (h ? ROWS.map(j => byteAt(h, j)) : [])

const isBuilt = (word: number) => word < props.nk + props.built
const isKey = (word: number) => word < props.nk
/** The word the last Next built, or none on the first view of the table. */
const current = computed(() => (props.built > 0 ? props.nk + props.built - 1 : null))
const tapped = ref<number | null>(null)
const shown = computed(() => tapped.value ?? current.value)
const shownRow = computed(() => (shown.value != null && !isKey(shown.value) ? rowOf(shown.value) : null))

// ---- The build in motion. `anim.word` is the word in play; null shows every row and every byte at once (the end frame).
const anim = reactive({ word: null as number | null, rows: 0, filled: 4, xor: null as number | null })
const phantom = ref<{ word: number; values: string[] } | null>(null)
const root = ref<HTMLElement | null>(null)
let token = 0

/** The byte in flight from the XOR line to its cell, at its start point on screen. */
const flyer = ref<{ text: string; left: number; top: number } | null>(null)

function endFrame() { token++; anim.word = null; anim.rows = 0; anim.filled = 4; anim.xor = null; phantom.value = null; flyer.value = null }

/** Keeps the step in play in view: the panel scrolls itself, so the round keys stay where they are (the lead on #326). */
async function reveal(run: number, selector: string) {
  await nextTick()
  if (run === token) root.value?.querySelector(selector)?.scrollIntoView({ block: 'nearest' })
}

/** The finished byte flies from the XOR line into its cell, as in the mock. It lands, and then the cell pulses. */
async function fly(run: number, r: AesKeyWordRow, j: number) {
  await nextTick()
  const from = root.value?.querySelector('.aw-ks-xor-out')
  const to = cellEl(r.i, j)
  if (!from || !to || !tl || run !== token) return
  const a = from.getBoundingClientRect(), b = to.getBoundingClientRect()
  flyer.value = { text: byteAt(r.word, j), left: a.left, top: a.top }
  await nextTick()
  const el = document.querySelector('[data-testid="aes-walk-ks-flyer"]')
  const move = el ? tl.animate(el, [{ transform: 'none' }, { transform: `translate(${b.left + b.width / 2 - a.left - 14}px, ${b.top + b.height / 2 - a.top - 12}px)` }], { duration: 520, easing: 'ease-in-out', fill: 'both' }) : null
  if (move) await move.finished.catch(() => null)
  if (run === token) flyer.value = null
}
const cellEl = (word: number, j: number) => root.value?.querySelector(`[data-testid="aes-walk-table-cell-${16 * Math.floor(word / 4) + j + 4 * (word % 4)}"]`) ?? null

/** One beat at `at` ms on the clock (the clock scales it by speed). Under reduced motion, or when the clock finishes or cancels it, it runs now. */
function beat(run: number, at: number, fn: () => void) {
  const go = () => { if (run === token) fn() }
  const a = root.value && tl ? tl.animate(root.value, [{ opacity: 1 }, { opacity: 1 }], { duration: 1, delay: at, fill: 'none' }) : null
  if (!a) go()
  else a.finished.then(go, go)
}

/** The gap between stage rows. A word with a lifted copy gets longer, so the copy's moves can be watched (the mock's stageGap). */
const gapOf = (r: AesKeyWordRow) => (r.rotated || r.substituted ? 950 : 420)
const stageCount = (r: AesKeyWordRow) => stagesOf(r).length

/** Plays a word's stage rows, and its lifted copy. With `fill`, the new word's 4 bytes land after the rows. */
function play(r: AesKeyWordRow, fill: boolean) {
  endFrame()
  if (!tl || tl.reduced()) return
  const run = token, gap = gapOf(r), n = stageCount(r)
  anim.word = r.i; anim.rows = 0; anim.filled = fill ? 0 : 4; anim.xor = null
  for (let k = 0; k < n; k++) beat(run, k * gap, () => { anim.rows = k + 1; void reveal(run, '.aw-ks-stage:last-child') })
  if (r.rotated || r.substituted) {
    beat(run, 0, () => { phantom.value = { word: r.i - 1, values: bytes(r.previous) } })
    if (r.rotated) {
      beat(run, gap, () => { void rotatePhantom(run, r) })
      beat(run, 2 * gap, () => { if (phantom.value) phantom.value = { ...phantom.value, values: bytes(r.substituted) } })
      beat(run, 3 * gap, () => { if (phantom.value) phantom.value = { ...phantom.value, values: [byteAt(r.afterRcon ?? '', 0), ...bytes(r.substituted).slice(1)] } })
    } else beat(run, gap, () => { if (phantom.value) phantom.value = { ...phantom.value, values: bytes(r.substituted) } })
  }
  const rowsDone = (n - 1) * gap + 280
  if (!fill) { beat(run, rowsDone + 400, () => { phantom.value = null; anim.word = null }); return }
  const BYTE = 1640
  for (let j = 0; j < 4; j++) {
    beat(run, rowsDone + j * BYTE, () => { anim.xor = j; void reveal(run, '.aw-ks-xor') })
    beat(run, rowsDone + j * BYTE + 800, () => { void fly(run, r, j) })
    beat(run, rowsDone + j * BYTE + 1320, () => { anim.filled = j + 1; void pulse(r.i, j) })
  }
  beat(run, rowsDone + 4 * BYTE, () => { endFrame() })
}

/** RotWord on the lifted copy: the strip moves up one byte, and the top byte wraps to the bottom. */
async function rotatePhantom(run: number, r: AesKeyWordRow) {
  await nextTick()
  const strip = root.value?.querySelector<HTMLElement>('.aw-ks-pstrip')
  const pitch = strip?.firstElementChild ? (strip.firstElementChild as HTMLElement).offsetHeight + 3 : 0
  const a = strip && tl ? tl.animate(strip, [{ transform: 'none' }, { transform: `translateY(${-pitch}px)` }], { duration: 720, fill: 'none' }) : null
  if (a) await a.finished.catch(() => null)
  if (run === token && phantom.value) phantom.value = { ...phantom.value, values: bytes(r.rotated) }
}

async function pulse(word: number, j: number) {
  await nextTick()
  const el = cellEl(word, j)
  if (el && tl) tl.animate(el, [{ transform: 'scale(1.16)' }, { transform: 'none' }], { duration: 260, fill: 'none' })
}

// A Next onto the next word plays its build. Any other move (Back, Start over, a new block) lands on the end frame.
watch(() => [props.built, props.block] as const, ([b, blk], [ob, oblk]) => {
  tapped.value = null
  const r = current.value != null ? rowOf(current.value) : null
  if (blk === oblk && b === ob + 1 && r) play(r, true)
  else endFrame()
})

/** A tap on a built word shows how it was made, and replays its rows. */
function tap(word: number) {
  if (!isBuilt(word)) return
  if (tl?.running.value) tl.finishNow()
  tapped.value = word
  const r = isKey(word) ? null : rowOf(word)
  if (r) play(r, false)
  else endFrame()
}

const filling = (word: number) => anim.word === word && anim.filled < 4
/** A cell's byte: empty until its word is built, and, while a word fills, until its own byte lands. */
function cellByte(word: number, j: number): string {
  if (!isBuilt(word)) return ''
  if (filling(word) && j >= anim.filled) return ''
  return byteAt(hex.value, 4 * word + j)
}

/** The role colors of the mock: the word built or tapped, the word before it, and the word Nk back. A key word has no sources. */
function roleOf(word: number): string | undefined {
  const s = shown.value
  if (s == null) return undefined
  if (word === s) return 'new'
  if (s < props.nk) return undefined
  if (word === s - 1) return 'previous'
  if (word === s - props.nk) return 'key-back'
  return undefined
}

interface Stage { id: string; label: string; values: string[]; role?: string; temp?: boolean }
/** The stage rows, in FIPS 197 order. A stage the engine did not run has no row. The temp row is the value the word Nk back meets. */
function stagesOf(r: AesKeyWordRow): Stage[] {
  const out: Stage[] = []
  const temp = r.afterRcon ? 'after-rcon' : r.substituted ? 'substituted' : 'previous'
  if (r.previous) out.push({ id: 'previous', label: `The word before, w${r.i - 1}`, values: bytes(r.previous), role: 'previous' })
  if (r.rotated) out.push({ id: 'rotated', label: 'RotWord: rotate one byte, up this column', values: bytes(r.rotated) })
  if (r.substituted) out.push({ id: 'substituted', label: r.rotated ? 'SubWord: the same S-box' : 'AES-256 only: SubWord', values: bytes(r.substituted) })
  if (r.rcon) out.push({ id: 'rcon', label: `Round constant ${r.quotient}`, values: bytes(r.rcon) })
  if (r.afterRcon) out.push({ id: 'after-rcon', label: 'XOR the round constant', values: bytes(r.afterRcon) })
  if (r.keyBack) out.push({ id: 'key-back', label: `XOR the word ${props.nk} back, w${r.i - props.nk}`, values: bytes(r.keyBack), role: 'key-back' })
  out.push({ id: 'word', label: `New word, w${r.i}`, values: bytes(r.word), role: 'new' })
  for (const s of out) s.temp = s.id === temp
  return out
}
const stages = computed(() => {
  const r = shownRow.value
  if (!r) return []
  const all = stagesOf(r)
  return anim.word === r.i ? all.slice(0, anim.rows) : all
})
/** A byte of the new word shows "--" until it lands. */
const stageByte = (s: Stage, j: number) => (s.id === 'word' && shownRow.value && filling(shownRow.value.i) && j >= anim.filled ? '--' : s.values[j])
/** The bytes in play during byte j's XOR: byte j of the word Nk back, the value it meets, and the new byte. */
const picked = (s: Stage, j: number) => anim.xor === j && (s.id === 'key-back' || s.temp || s.id === 'word')
const xorLine = computed(() => {
  const r = shownRow.value, j = anim.xor
  if (!r || j == null || !r.keyBack) return null
  const temp = r.afterRcon ?? r.substituted ?? r.previous ?? ''
  return { j, back: byteAt(r.keyBack, j), meets: byteAt(temp, j), out: byteAt(r.word, j), from: r.i - props.nk, to: r.i }
})
const bits = (h: string) => { const b = parseInt(h, 16).toString(2).padStart(8, '0'); return `${b.slice(0, 4)} ${b.slice(4)}` }

const title = computed(() => (shown.value == null ? gloss.keys.fillsKey.replace('{last}', String(props.nk - 1)) : gloss.keys.madeOf.replace('{i}', String(shown.value))))
const keyNote = computed(() => shown.value != null && isKey(shown.value))
const why = computed(() => {
  const r = shownRow.value
  if (!r || (!r.rotated && !r.substituted)) return ''
  return (r.rotated ? gloss.keys.rotCopy : gloss.keys.subCopy).replace(/\{prev\}/g, String(r.i - 1)).replace('{i}', String(r.i))
})

const bandNote = computed(() => (props.nk === 6 ? gloss.keys.band192 : props.nk === 8 ? gloss.keys.band256 : ''))
const rcon = computed(() => Array.from({ length: props.tables.rcon.length / 2 }, (_, n) => byteAt(props.tables.rcon, n)))
const used = computed(() => size.value?.rconUsed ?? rcon.value.length)
/** The round constant a rotating word uses: number i / Nk, so chip i / Nk - 1. A plain word uses none. */
const rconLit = computed(() => (shownRow.value?.rotated ? shownRow.value.i / props.nk - 1 : -1))

// ---- Zoom (Steve's fix 3): the round keys only. The grids wrap, so no zoom scrolls the page sideways.
const ZOOMS = [0.75, 0.85, 1, 1.2, 1.45]
const zoomAt = ref(2)
const zoomBy = (d: number) => { zoomAt.value = Math.max(0, Math.min(ZOOMS.length - 1, zoomAt.value + d)) }
function onWheel(e: WheelEvent) {
  if (!e.ctrlKey) return
  e.preventDefault()
  zoomBy(e.deltaY < 0 ? 1 : -1)
}
const tableStyle = computed(() => ({ '--ks-zoom': String(ZOOMS[zoomAt.value]) }))

const cellIdOf = (g: number, r: number, c: number) => 16 * (g - 1) + r + 4 * c
const wordOf = (g: number, c: number) => 4 * (g - 1) + c
</script>

<template>
  <div ref="root" class="aw-ks" data-testid="aes-walk-key-schedule">
    <div class="aw-ks-words">
      <p>{{ gloss.keys.start }}</p>
      <p>{{ [gloss.keys.eachRound, nk === 4 ? gloss.keys.only128 : '', gloss.keys.decrypt].filter(Boolean).join(' ') }}</p>
      <p v-if="bandNote" class="aw-ks-band-note" data-testid="aes-walk-key-band-note">{{ bandNote }}</p>
    </div>
    <div class="aw-ks-bench">
      <div class="aw-ks-left">
        <div class="aw-ks-tools">
          <span class="muted">Zoom</span>
          <v-btn size="small" variant="outlined" :disabled="zoomAt === 0" icon="mdi-magnify-minus-outline" aria-label="Zoom out" data-testid="aes-walk-ks-zoom-out" @click="zoomBy(-1)" />
          <v-btn size="small" variant="outlined" :disabled="zoomAt === 2" data-testid="aes-walk-ks-zoom-reset" @click="zoomAt = 2">{{ Math.round(ZOOMS[zoomAt] * 100) }}%</v-btn>
          <v-btn size="small" variant="outlined" :disabled="zoomAt === ZOOMS.length - 1" icon="mdi-magnify-plus-outline" aria-label="Zoom in" data-testid="aes-walk-ks-zoom-in" @click="zoomBy(1)" />
          <v-btn size="small" variant="text" class="ml-4" :disabled="built === 0" data-testid="aes-walk-ks-start-over" @click="emit('startOver')">Start over</v-btn>
        </div>
        <div class="aw-ks-table" role="list" aria-label="The expanded key, one grid per round key" :style="tableStyle" data-testid="aes-walk-ks-table" @wheel="onWheel">
          <div v-for="g in grids" :key="g" class="aw-ks-grid-wrap" role="listitem">
            <span class="aw-ks-grid-name muted">Round key {{ g - 1 }}</span>
            <div class="aw-ks-grid" :data-testid="`aes-walk-table-grid-${g - 1}`">
              <template v-for="r in ROWS" :key="r">
                <button
                  v-for="c in ROWS" :key="c" type="button" class="aw-ks-cell"
                  :class="{ 'aw-ks-key': isKey(wordOf(g, c)), 'aw-ks-unbuilt': !isBuilt(wordOf(g, c)), 'aw-ks-pick': anim.xor === r && (wordOf(g, c) === (shownRow?.i ?? -9) - nk || (!phantom && wordOf(g, c) === (shownRow?.i ?? -9) - 1 && r === (shownRow?.rotated ? (anim.xor + 1) % 4 : anim.xor))) }"
                  :data-testid="`aes-walk-table-cell-${cellIdOf(g, r, c)}`"
                  :data-word="`w${wordOf(g, c)}`"
                  :data-hex="cellByte(wordOf(g, c), r)"
                  :data-key="isKey(wordOf(g, c)) ? 'true' : undefined"
                  :data-role="roleOf(wordOf(g, c))"
                  :style="{ gridColumn: c + 1, gridRow: r + 1 }"
                  :aria-label="`byte ${cellIdOf(g, r, c)}, word w${wordOf(g, c)}`"
                  @click="tap(wordOf(g, c))"
                >
                  <span class="aw-ks-hex">{{ cellByte(wordOf(g, c), r) }}</span>
                  <span class="aw-ks-pos">{{ cellIdOf(g, r, c) }}</span>
                  <span class="aw-ks-word">w{{ wordOf(g, c) }}</span>
                </button>
              </template>
              <!-- The lifted copy of the word before: it rotates and changes here, and the word before itself does not change. -->
              <div v-if="phantom && Math.floor(phantom.word / 4) === g - 1" class="aw-ks-phantom" :style="{ gridColumn: (phantom.word % 4) + 1, gridRow: '1 / span 4' }" data-testid="aes-walk-ks-phantom" aria-hidden="true">
                <div class="aw-ks-pstrip">
                  <div v-for="(v, j) in phantom.values" :key="j" class="aw-ks-pcell" :class="{ 'aw-ks-pick': anim.xor === j }">{{ v }}</div>
                  <div class="aw-ks-pcell">{{ phantom.values[0] }}</div>
                </div>
              </div>
            </div>
          </div>
        </div>
        <p class="muted aw-ks-tap">{{ gloss.keys.tapHint }}</p>
      </div>
      <div class="aw-ks-build" data-testid="aes-walk-ks-build">
        <h3 class="aw-ks-title" data-testid="aes-walk-ks-build-title">{{ title }}</h3>
        <p v-if="keyNote" class="aw-ks-key-note" data-testid="aes-walk-build-key-note">w{{ shown }}: {{ gloss.keys.keyNote }}</p>
        <template v-else-if="shownRow">
          <p class="aw-ks-test">{{ wordTest(shownRow, nk) }}</p>
          <div class="aw-ks-stages">
            <div v-for="s in stages" :key="s.id" class="aw-ks-stage" :class="`aw-ks-stage-${s.id}`" :data-role="s.role" :data-testid="`aes-walk-build-${s.id}`">
              <span class="aw-ks-stage-label">{{ s.label }}</span>
              <code class="aw-ks-chips"><span v-for="j in ROWS" :key="j" class="aw-ks-chip" :class="{ 'aw-ks-pick': picked(s, j) }">{{ stageByte(s, j) }}</span></code>
            </div>
          </div>
          <div v-if="xorLine" class="aw-ks-xor" data-testid="aes-walk-build-xor" aria-live="polite">
            <div class="aw-ks-xor-top"><span class="aw-ks-xor-back">{{ xorLine.back }}</span> XOR <span>{{ xorLine.meets }}</span> = <span class="aw-ks-xor-out">{{ xorLine.out }}</span></div>
            <pre class="aw-ks-xor-bits">{{ `w${xorLine.from} byte ${xorLine.j}`.padEnd(13) }}{{ bits(xorLine.back) }}
{{ 'XOR'.padEnd(13) }}{{ bits(xorLine.meets) }}
{{ `w${xorLine.to} byte ${xorLine.j}`.padEnd(13) }}{{ bits(xorLine.out) }}</pre>
          </div>
          <p v-if="why" class="aw-ks-why" data-testid="aes-walk-ks-why">{{ why }}</p>
        </template>
        <div class="aw-ks-rcon-block">
          <p class="muted">{{ gloss.keys.rcon }}</p>
          <div class="aw-ks-rcon" data-testid="aes-walk-rcon">
            <span v-for="(v, n) in rcon" :key="n" class="aw-ks-rcon-chip" :class="{ 'aw-ks-rcon-unused': n >= used }" :data-lit="n === rconLit ? 'true' : undefined" :data-testid="`aes-walk-rcon-${n}`">{{ v }}</span>
          </div>
          <p v-if="used < rcon.length" class="muted">{{ gloss.keys.rconUnused.replace('{bits}', String(block.keyBits)).replace('{used}', String(used)) }}</p>
        </div>
      </div>
    </div>
    <!-- The flying byte rides in the overlay layer, outside the walk's clip. -->
    <Teleport to=".overlay-layer">
      <div v-if="flyer" class="aw-ks-flyer" data-testid="aes-walk-ks-flyer" :style="{ left: `${flyer.left}px`, top: `${flyer.top}px` }" aria-hidden="true">{{ flyer.text }}</div>
    </Teleport>
  </div>
</template>
