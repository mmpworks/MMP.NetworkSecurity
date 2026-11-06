<script setup lang="ts">
import { computed } from 'vue'
import { words } from '../security'
import { active, shownEvents } from '../store'

// One chip per key the lesson took at its start: the type, the key version, and whose key it is. With Show keys OFF the chip shows the fingerprint.
const chips = computed(() => shownEvents.value.filter(e => e.type === 'key.in-use').map(e => {
  const s = e.secrets[0]
  const value = !s ? '' : s.hex ? (s.hex.length > 24 ? `${s.hex.slice(0, 16)}…${s.hex.slice(-8)}` : s.hex) : s.fingerprint
  return { typeId: e.typeId, version: e.version, builtin: e.provider === 'builtin', value }
}))
</script>

<template>
  <div v-if="chips.length" class="keys-in-use" data-testid="keys-in-use">
    <div class="side-title">{{ words('wizard.keys.in-use.title') }}</div>
    <div class="muted">{{ words('wizard.keys.in-use.note') }}</div>
    <div class="kiu-chips">
      <span v-for="c in chips" :key="c.typeId" class="kiu-chip" :data-testid="`key-in-use-${c.typeId}`">
        <b>{{ words(`wizard.type.${c.typeId}.title`, c.typeId) }}</b>
        <span class="muted">{{ c.builtin ? words('wizard.chip.builtin') : 'My test key' }}{{ c.version > 0 ? `, version ${c.version}` : '' }}</span>
        <code v-if="c.value" :data-testid="`key-in-use-value-${c.typeId}`">{{ c.value }}</code>
      </span>
    </div>
  </div>
  <div v-if="active?.fileHidesKeys" class="muted" data-testid="replay-hides-keys">{{ words('wizard.keys.replay-off') }}</div>
</template>
