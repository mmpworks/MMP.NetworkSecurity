<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import gloss from '../walk-gloss.json'
import { CURRENT_STRIP_BLOCK as CURRENT_BLOCK, LESSON_TEXT, aesWalk, describe, postJson } from '../aesWalkState'
import { hostState } from '../store'
import { textOf, type AesLongRow } from '../walk'

// The long text, pinned above the walk in Techniques (docs/sections-plan.md R1 and item 2; Q3, Steve: A). One mono line of the text,
// one box per 16-byte block, with the block the walk shows marked current. It reads the rows of POST /api/walk/aes/long-text, which
// runs on the public practice key and reads no run, so it shows with Show keys off too. Typed text prints as text, never as HTML.

const rows = ref<AesLongRow[]>([])
const error = ref('')
let gen = 0

const text = computed(() => aesWalk.typed || LESSON_TEXT)

async function load() {
  const mine = ++gen
  error.value = ''
  try {
    const body = await postJson('/api/walk/aes/long-text', { text: text.value, keyBits: aesWalk.keyBits })
    if (mine === gen) rows.value = (body?.rows ?? []) as AesLongRow[]
  } catch (e) {
    if (mine === gen) { rows.value = []; error.value = describe(e) }
  }
}

// The box's text is already debounced in the walk state, so the strip asks once per settled text.
watch([text, () => aesWalk.keyBits, hostState], ([, , s]) => { if (s === 'connected') void load() }, { immediate: true })

/** The 16 characters a block holds. A byte that is not a printable character, such as padding, shows as '·', so it cannot pass for a '.' in the text (Richard and Jared on #270). */
const blockText = (row: AesLongRow) => textOf(row.data, '·')
</script>

<template>
  <div class="aw-strip" data-testid="aes-long-strip">
    <!-- The blocks scroll in their own row, so the legend beside them never scrolls away or gets cut (Richard and the lead on #270). -->
    <div class="aw-strip-blocks" role="list" :aria-label="gloss.strip.label" tabindex="0">
      <span v-if="error" class="aw-strip-error">{{ error }}</span>
      <span
        v-for="(row, n) in rows" :key="n" role="listitem" class="aw-strip-block" :class="{ 'aw-strip-current': n === CURRENT_BLOCK }"
        :data-testid="`aes-long-block-${n}`" :data-current="n === CURRENT_BLOCK ? 'true' : undefined"
        :title="n === CURRENT_BLOCK ? gloss.strip.current.replace('{n}', String(n + 1)) : `Block ${n + 1}`"
      ><span class="aw-strip-n">{{ n + 1 }}</span>{{ blockText(row) }}</span>
    </div>
    <!-- At the right end, so block 1 stays at the left edge where the link line starts. It also names the strip on items that are not AES.
         data-show-whole: the layout sweep fails if any part of it is cut. -->
    <span class="aw-strip-legend" data-testid="aes-long-legend" data-show-whole>{{ gloss.strip.legend }}</span>
  </div>
</template>
