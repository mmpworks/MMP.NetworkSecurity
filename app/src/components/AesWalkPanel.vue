<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import gloss from '../walk-gloss.json'
import { DEFAULT_BLOCK_TEXT, KEY_SIZES, aesWalk, choosePractice, isPractice, loadAesTables, pickKeyBits, refreshAesWalk, setTypedText } from '../aesWalkState'
import { sec } from '../security'
import { hostState, ui } from '../store'
import { splitAtBytes } from '../walk'
import AesBlockWalk from './AesBlockWalk.vue'
import SboxView from './SboxView.vue'

// The AES walk in Techniques. It shows a lesson run's block, or the practice walk on the learner's own text (design 2.2g).
// With Show keys off the run's steps stay closed (design section 3.5), the public S-box table stays on screen (design 2.3),
// and the practice walk stays open, because its key is public.
function backToLesson() { ui.section = 'lessons' }

const practice = computed(() => isPractice())
/** The run's walk is closed while Show keys is off. The practice walk never is. */
const closed = computed(() => !practice.value && !sec.showKeys)

onMounted(() => {
  aesWalk.opened = true
  if (!aesWalk.block && !aesWalk.loading && hostState.value === 'connected') refreshAesWalk()
})

watch([() => sec.showKeys, hostState], ([on, state]) => {
  if (!on && state === 'connected') loadAesTables().catch(() => { /* the tables come with the next connect */ })
}, { immediate: true })

// The box sends its text after a short pause in typing, so each key press does not ask the engine again.
const draft = ref(aesWalk.typed)
watch(() => aesWalk.typed, t => { if (t !== draft.value) draft.value = t })
let pause = 0
watch(draft, t => { window.clearTimeout(pause); pause = window.setTimeout(() => setTypedText(t ?? ''), 350) })
onBeforeUnmount(() => window.clearTimeout(pause))

/** The box marks what the block uses, a character split at byte 16, and the rest, from the engine's cut. */
const marks = computed(() => (aesWalk.cut && aesWalk.typed ? splitAtBytes(aesWalk.typed, aesWalk.cut.usedBytes) : null))

const wireLine = computed(() => {
  const b = aesWalk.block
  if (!b?.wire) return ''
  // With the box empty, the practice block is lesson 1's own text, which the run did send, so "did not go on the wire" would be false (Richard on #270).
  if (b.source === 'typed') return aesWalk.typed ? gloss.wireTyped : ''
  return (gloss.wire as Record<string, string>)[b.wire.status] ?? ''
})
const keyLine = computed(() => {
  const s = aesWalk.block?.keySource
  if (!s) return ''
  // With no run on screen there is no "run's key" to compare with, so the practice line leaves those words out (Jared on #270).
  const words = gloss.keySource as Record<string, string>
  if (s === 'typed-practice' && !aesWalk.sessionId) return words['typed-practice-no-run']
  return words[s] ?? `Key source: ${s}`
})
const showsWalk = computed(() => !closed.value && !!aesWalk.block)
</script>

<template>
  <section class="aes-walk-panel" data-testid="aes-walk-panel">
    <header class="aw-title">
      <h2>AES: inside one block</h2>
      <span v-if="aesWalk.lesson != null && !practice" class="muted">The block from lesson {{ aesWalk.lesson }}'s run</span>
      <span v-else class="muted" data-testid="aes-walk-subtitle">{{ aesWalk.typed ? gloss.typed.subtitleTyped : gloss.typed.subtitleLesson }}</span>
      <v-spacer />
      <div v-if="!closed && (aesWalk.sessionId || practice)" class="aw-sizes" role="radiogroup" aria-label="Key size">
        <span class="muted">Key size</span>
        <v-btn
          v-for="bits in KEY_SIZES" :key="bits" size="small" role="radio" :aria-checked="aesWalk.keyBits === bits"
          :variant="aesWalk.keyBits === bits ? 'flat' : 'outlined'" :color="aesWalk.keyBits === bits ? 'primary' : undefined"
          :data-testid="`aes-walk-key-size-${bits}`" @click="pickKeyBits(bits)"
        >{{ bits }}-bit</v-btn>
      </div>
      <v-btn v-if="aesWalk.lesson != null" variant="text" prepend-icon="mdi-arrow-left" data-testid="aes-walk-back-to-lesson" @click="backToLesson">Back to lesson {{ aesWalk.lesson }}</v-btn>
    </header>

    <!-- Design 2.2g: one box. The engine cuts the first 16 bytes; the box marks what the block does not use. Typed text prints as text, never as HTML. -->
    <div class="aw-typed">
      <v-text-field
        v-model="draft" :label="gloss.typed.label" :placeholder="DEFAULT_BLOCK_TEXT" density="compact" variant="outlined" hide-details clearable
        data-testid="aes-walk-text" class="aw-typed-box"
      />
      <p v-if="marks" class="aw-typed-marks" data-testid="aes-walk-text-marks">
        <span class="aw-typed-in">{{ marks.inside }}</span><span v-if="marks.split" class="aw-typed-split">{{ marks.split }}</span><span v-if="marks.outside" class="aw-typed-out" data-testid="aes-walk-text-not-included">{{ marks.outside }}</span>
        <span v-if="marks.outside || marks.split" class="aw-typed-tag">{{ gloss.typed.notIncluded }}</span>
      </p>
      <p v-if="aesWalk.cut && aesWalk.typed" class="muted aw-note">
        {{ gloss.typed.bytes }}
        <template v-if="aesWalk.cut.splitCharacterBytesIn"> {{ gloss.typed.split.replace('{n}', String(aesWalk.cut.splitCharacterBytesIn)) }}</template>
        <template v-if="aesWalk.cut.paddingBytes"> {{ gloss.typed.padding }}</template>
        <template v-else-if="!aesWalk.cut.notIncludedBytes"> {{ gloss.typed.full }}</template>
      </p>
    </div>

    <!-- Design 2.7 and 2.2g: which key the walk shows, read from the reply's keySource, and whether this block went on the wire. -->
    <p v-if="showsWalk && keyLine" class="aw-key-source" :class="`aw-key-source-${aesWalk.block?.keySource}`" data-testid="aes-walk-key-source">{{ keyLine }}</p>
    <p v-if="showsWalk && practice && aesWalk.sessionId" class="muted aw-note" data-testid="aes-walk-key-differs">
      {{ gloss.typed.differs }}
      <v-btn v-if="aesWalk.chosePractice && !aesWalk.typed" size="small" variant="text" data-testid="aes-walk-back-to-run" @click="choosePractice(false)">{{ gloss.typed.backToRun }}</v-btn>
    </p>
    <p v-if="showsWalk && wireLine" class="muted aw-note" data-testid="aes-walk-wire-label" :data-status="aesWalk.block?.wire?.status">{{ wireLine }}</p>

    <template v-if="closed">
      <p class="aw-closed" data-testid="aes-walk-closed">{{ gloss.closed }}</p>
      <v-btn variant="tonal" size="small" class="aw-offer" data-testid="aes-walk-practice-offer" @click="choosePractice(true)">{{ gloss.typed.offer }}</v-btn>
      <SboxView v-if="aesWalk.tables" :table="aesWalk.tables.sbox" byte="" :inverse="false" no-grid />
    </template>
    <p v-else-if="aesWalk.closedBySocket && !aesWalk.block" class="muted aw-note" data-testid="aes-walk-offline">The connection to the engine closed. The walk comes back when it reconnects.</p>
    <p v-else-if="aesWalk.error" class="aw-error" data-testid="aes-walk-error">The engine could not build the walk: {{ aesWalk.error }}</p>
    <p v-else-if="aesWalk.loading || !aesWalk.block || !aesWalk.tables" class="muted aw-note">Asking the engine for the block...</p>
    <AesBlockWalk v-else :block="aesWalk.block" :tables="aesWalk.tables" />
  </section>
</template>
