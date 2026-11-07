<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import gloss from '../walk-gloss.json'
import { byteAt, expandedHex, wordTest, type AesBlockReply, type AesTables } from '../walk'

// The key schedule (design section 2.2b): the expanded table, one grid per round key, built one word per Next.
// Every byte is from the reply's keyWords rows. Grid, column, and byte position come from the word index by layout only.
const props = defineProps<{ block: AesBlockReply; tables: AesTables; nk: number; built: number }>()

const rows = computed(() => props.block.keyWords.slice().sort((a, b) => a.i - b.i))
const hex = computed(() => expandedHex(rows.value))
const grids = computed(() => rows.value.length / 4)
const size = computed(() => props.tables.sizes.find(s => s.keyBits === props.block.keyBits))
const ROWS = [0, 1, 2, 3]

const isBuilt = (word: number) => word < props.nk + props.built
const isKey = (word: number) => word < props.nk
/** The word the last Next built, or none on the first view of the table. */
const current = computed(() => (props.built > 0 ? props.nk + props.built - 1 : null))

// A tap picks a built word. A new stop drops the pick, so the panel follows the word Next just built.
const tapped = ref<number | null>(null)
watch(() => [props.built, props.block], () => { tapped.value = null })
const shown = computed(() => tapped.value ?? current.value)
const shownRow = computed(() => (shown.value != null && !isKey(shown.value) ? rows.value.find(r => r.i === shown.value) ?? null : null))
const keyNote = computed(() => shown.value != null && isKey(shown.value))

/** The two words the shown word comes from: the one before it, and the one Nk back. A key word comes from none. */
const lit = computed(() => (shownRow.value ? new Set([shownRow.value.i - 1, shownRow.value.i - props.nk]) : new Set<number>()))

function tap(word: number) {
  if (!isBuilt(word)) return
  tapped.value = word
}

const cellByte = (p: number) => (isBuilt(Math.floor(p / 4)) ? byteAt(hex.value, p) : '')

/** The stage rows of the shown word, in FIPS 197 order. A stage the engine did not run has no row. */
const stages = computed(() => {
  const r = shownRow.value
  if (!r) return []
  const w = `w${r.i}`
  const out: { id: string; label: string; value: string }[] = []
  if (r.previous) out.push({ id: 'previous', label: `w${r.i - 1}, the word before`, value: r.previous })
  if (r.rotated) out.push({ id: 'rotated', label: 'RotWord: rotate one byte, up this column', value: r.rotated })
  if (r.substituted) out.push({ id: 'substituted', label: 'SubWord: the same S-box', value: r.substituted })
  if (r.rcon) out.push({ id: 'rcon', label: `Round constant ${r.quotient}`, value: r.rcon })
  if (r.afterRcon) out.push({ id: 'after-rcon', label: 'XOR the round constant', value: r.afterRcon })
  if (r.keyBack) out.push({ id: 'key-back', label: `w${r.i - props.nk}, ${props.nk} words back`, value: r.keyBack })
  out.push({ id: 'word', label: `XOR the two, so ${w}`, value: r.word })
  return out
})

const bandNote = computed(() => (props.nk === 6 ? gloss.keys.band192 : props.nk === 8 ? gloss.keys.band256 : ''))
const rcon = computed(() => Array.from({ length: props.tables.rcon.length / 2 }, (_, n) => byteAt(props.tables.rcon, n)))
const used = computed(() => size.value?.rconUsed ?? rcon.value.length)
/** The round constant the shown word uses, found by its first byte, because the 10 values differ. */
const rconLit = computed(() => (shownRow.value?.rcon ? byteAt(shownRow.value.rcon, 0) : ''))
</script>

<template>
  <div class="ks" data-testid="aes-walk-key-schedule">
    <div class="ks-words">
      <p>{{ gloss.keys.start }}</p>
      <p>{{ [gloss.keys.eachRound, nk === 4 ? gloss.keys.only128 : '', gloss.keys.decrypt].filter(Boolean).join(' ') }}</p>
      <p v-if="bandNote" class="ks-band-note" data-testid="aes-walk-key-band-note">{{ bandNote }}</p>
    </div>
    <div class="ks-table" role="list" aria-label="The expanded key, one grid per round key">
      <div v-for="g in grids" :key="g" class="ks-grid-wrap" role="listitem">
        <span class="ks-grid-name muted">Round key {{ g - 1 }}</span>
        <div class="ks-grid" :data-testid="`aes-walk-table-grid-${g - 1}`">
          <template v-for="r in ROWS" :key="r">
            <button
              v-for="c in ROWS" :key="c" type="button" class="ks-cell"
              :class="{ 'ks-key': isKey(4 * (g - 1) + c), 'ks-lit': lit.has(4 * (g - 1) + c), 'ks-shown': shown === 4 * (g - 1) + c }"
              :data-testid="`aes-walk-table-cell-${16 * (g - 1) + r + 4 * c}`"
              :data-word="`w${4 * (g - 1) + c}`"
              :data-hex="cellByte(16 * (g - 1) + r + 4 * c)"
              :data-key="isKey(4 * (g - 1) + c) ? 'true' : undefined"
              :data-lit="lit.has(4 * (g - 1) + c) ? 'true' : undefined"
              :aria-label="`byte ${16 * (g - 1) + r + 4 * c}, word w${4 * (g - 1) + c}`"
              @click="tap(4 * (g - 1) + c)"
            >
              <span class="ks-pos">{{ 16 * (g - 1) + r + 4 * c }}</span>
              <span class="ks-hex">{{ cellByte(16 * (g - 1) + r + 4 * c) }}</span>
              <span class="ks-word">w{{ 4 * (g - 1) + c }}</span>
            </button>
          </template>
        </div>
      </div>
    </div>
    <div class="ks-side">
      <p v-if="keyNote" class="ks-key-note" data-testid="aes-walk-build-key-note">w{{ shown }}: {{ gloss.keys.keyNote }}</p>
      <template v-else-if="shownRow">
        <p class="ks-test">{{ wordTest(shownRow, nk) }}</p>
        <dl class="ks-stages">
          <div v-for="s in stages" :key="s.id" class="ks-stage" :class="`ks-stage-${s.id}`" :data-testid="`aes-walk-build-${s.id}`">
            <dt>{{ s.label }}</dt>
            <dd>{{ s.value }}</dd>
          </div>
        </dl>
      </template>
      <div class="ks-rcon-block">
        <p class="muted">{{ gloss.keys.rcon }}</p>
        <div class="ks-rcon" data-testid="aes-walk-rcon">
          <span v-for="(v, n) in rcon" :key="n" :class="{ 'ks-rcon-unused': n >= used, 'ks-rcon-lit': v === rconLit }">{{ v }}</span>
        </div>
        <p v-if="used < rcon.length" class="muted">{{ gloss.keys.rconUnused.replace('{bits}', String(block.keyBits)).replace('{used}', String(used)) }}</p>
      </div>
    </div>
  </div>
</template>
