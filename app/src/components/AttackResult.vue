<script setup lang="ts">
import { computed } from 'vue'
import { active, allEvents } from '../store'

// Result of an attack fork: the check that caught it, by name, or a plain statement that no check did (ux-design.md section 7).
// The name comes from session.finished when the engine says `caught`. A peer can report PEER_CLOSED_EARLY first, and that is not the catch.
const fork = computed(() => (active.value?.parentId ? active.value : null))
const fin = computed(() => fork.value?.finished ?? null)
const caught = computed(() => {
  if (fin.value?.outcome === 'caught' && fin.value.check) return { name: fin.value.check, code: fin.value.code }
  const e = allEvents.value.find(x => x.check?.result === 'fail')?.check
  return e ? { name: e.name, code: e.code } : null
})
</script>

<template>
  <div v-if="fork" class="attack-result" data-testid="attack-result">
    <div class="side-title">{{ fork.label }}</div>
    <div v-if="caught">Caught by <b data-testid="check-name">{{ caught.name }}</b> <span class="muted">({{ caught.code }})</span></div>
    <div v-else-if="fin">The session ended: {{ fin.outcome }}{{ fin.check ? `, check ${fin.check}` : '' }}{{ fin.code ? ` (${fin.code})` : '' }}</div>
    <div v-else class="muted">The tampered session is running. If it stops and waits, the receiver is still waiting for bytes that never came.</div>
  </div>
</template>
