<script setup lang="ts">
import { watch } from 'vue'
import gloss from '../walk-gloss.json'
import { KEY_SIZES, aesWalk, loadAesTables, pickKeyBits } from '../aesWalkState'
import { sec } from '../security'
import { hostState, ui } from '../store'
import AesBlockWalk from './AesBlockWalk.vue'
import SboxView from './SboxView.vue'

// The AES walk in Techniques. It shows a lesson run's block. With Show keys off the steps stay closed (design section 3.5),
// and the public S-box table stays on screen (design section 2.3).
function backToLesson() { ui.section = 'lessons' }

watch([() => sec.showKeys, hostState], ([on, state]) => {
  if (!on && state === 'connected') loadAesTables().catch(() => { /* the tables come with the next connect */ })
}, { immediate: true })

const wireLine = (status: string) => (gloss.wire as Record<string, string>)[status] ?? ''
</script>

<template>
  <section class="aes-walk-panel" data-testid="aes-walk-panel">
    <header class="aw-title">
      <h2>AES: inside one block</h2>
      <span v-if="aesWalk.lesson != null" class="muted">The block from lesson {{ aesWalk.lesson }}'s run</span>
      <v-spacer />
      <div v-if="sec.showKeys && aesWalk.sessionId" class="aw-sizes" role="radiogroup" aria-label="Key size">
        <span class="muted">Key size</span>
        <v-btn
          v-for="bits in KEY_SIZES" :key="bits" size="small" role="radio" :aria-checked="aesWalk.keyBits === bits"
          :variant="aesWalk.keyBits === bits ? 'flat' : 'outlined'" :color="aesWalk.keyBits === bits ? 'primary' : undefined"
          :data-testid="`aes-walk-key-size-${bits}`" @click="pickKeyBits(bits)"
        >{{ bits }}-bit</v-btn>
      </div>
      <v-btn v-if="aesWalk.lesson != null" variant="text" prepend-icon="mdi-arrow-left" data-testid="aes-walk-back-to-lesson" @click="backToLesson">Back to lesson {{ aesWalk.lesson }}</v-btn>
    </header>
    <!-- Design section 2.7: at 128 bits the walk uses the run's key, and at 192 and 256 bits a practice key. keySource in the reply says which. -->
    <p v-if="sec.showKeys && aesWalk.block?.keySource" class="aw-key-source" :class="`aw-key-source-${aesWalk.block.keySource}`" data-testid="aes-walk-key-source">
      {{ (gloss.keySource as Record<string, string>)[aesWalk.block.keySource] ?? `Key source: ${aesWalk.block.keySource}` }}
    </p>
    <!-- Design section 2.2g: the label says whether this run sent the block in ECB, from the reply's wire status. -->
    <p v-if="sec.showKeys && aesWalk.block?.wire && wireLine(aesWalk.block.wire.status)" class="muted aw-note" data-testid="aes-walk-wire-label" :data-status="aesWalk.block.wire.status">
      {{ wireLine(aesWalk.block.wire.status) }}
    </p>
    <template v-if="!sec.showKeys">
      <p class="aw-closed" data-testid="aes-walk-closed">{{ gloss.closed }}</p>
      <SboxView v-if="aesWalk.tables" :table="aesWalk.tables.sbox" byte="" :inverse="false" no-grid />
    </template>
    <p v-else-if="!aesWalk.sessionId" class="muted aw-note" data-testid="aes-walk-no-run">Open lesson 1 and pick the AES walk tab in the Message bytes panel. Typing your own text comes in a later update.</p>
    <p v-else-if="aesWalk.closedBySocket && !aesWalk.block" class="muted aw-note" data-testid="aes-walk-offline">The connection to the engine closed. The walk comes back when it reconnects.</p>
    <p v-else-if="aesWalk.error" class="aw-error" data-testid="aes-walk-error">The engine could not build the walk: {{ aesWalk.error }}</p>
    <p v-else-if="aesWalk.loading || !aesWalk.block || !aesWalk.tables" class="muted aw-note">Asking the engine for the block...</p>
    <AesBlockWalk v-else :block="aesWalk.block" :tables="aesWalk.tables" />
  </section>
</template>
