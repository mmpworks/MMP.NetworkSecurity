<script setup lang="ts">
import gloss from '../walk-gloss.json'
import { aesWalk } from '../aesWalkState'
import { sec } from '../security'
import { ui } from '../store'
import AesBlockWalk from './AesBlockWalk.vue'

// The AES walk in Techniques. It shows a lesson run's block. With Show keys off the steps stay closed (design section 3.5).
function backToLesson() { ui.section = 'lessons' }
</script>

<template>
  <section class="aes-walk-panel" data-testid="aes-walk-panel">
    <header class="aw-title">
      <h2>AES: inside one block</h2>
      <span v-if="aesWalk.lesson != null" class="muted">The block from lesson {{ aesWalk.lesson }}'s run</span>
      <v-spacer />
      <v-btn v-if="aesWalk.lesson != null" variant="text" prepend-icon="mdi-arrow-left" data-testid="aes-walk-back-to-lesson" @click="backToLesson">Back to lesson {{ aesWalk.lesson }}</v-btn>
    </header>
    <p v-if="!sec.showKeys" class="aw-closed" data-testid="aes-walk-closed">{{ gloss.closed }}</p>
    <p v-else-if="!aesWalk.sessionId" class="muted aw-note" data-testid="aes-walk-no-run">Open lesson 1 and pick the AES walk tab in the Message bytes panel. Typing your own text arrives in slice P2d.</p>
    <p v-else-if="aesWalk.closedBySocket && !aesWalk.block" class="muted aw-note" data-testid="aes-walk-offline">The connection to the engine closed. The walk comes back when it reconnects.</p>
    <p v-else-if="aesWalk.error" class="aw-error" data-testid="aes-walk-error">The engine could not build the walk: {{ aesWalk.error }}</p>
    <p v-else-if="aesWalk.loading || !aesWalk.block" class="muted aw-note">Asking the engine for the block...</p>
    <AesBlockWalk v-else :block="aesWalk.block" />
  </section>
</template>
