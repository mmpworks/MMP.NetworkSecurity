<script setup lang="ts">
import { setMode, ui } from '../store'

// Tour or Free play, inside the Lessons section: it heads the panel that shows the mode.
const MODES = [['tour', 'Tour'], ['free', 'Free play']] as const
</script>

<template>
  <span class="seg seg-small" role="group" aria-label="Mode" data-testid="mode-switch">
    <button v-for="[id, label] in MODES" :key="id" type="button" :aria-pressed="ui.mode === id" :data-testid="`mode-${id}`" @click="setMode(id)">{{ label }}</button>
  </span>
</template>
