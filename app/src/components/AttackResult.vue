<script setup lang="ts">
import { computed } from 'vue'
import { active, allEvents } from '../store'

// Result of an attack fork: the check that caught it, by name, or a plain statement that no check did (ux-design.md section 7).
const fork = computed(() => (active.value?.parentId ? active.value : null))
const failed = computed(() => allEvents.value.find(e => e.check?.result === 'fail')?.check ?? null)
const fin = computed(() => fork.value?.finished ?? null)
</script>

<template>
  <div v-if="fork" class="attack-result" data-testid="attack-result">
    <div class="side-title">{{ fork.label }}</div>
    <div v-if="failed">Caught by <b data-testid="check-name">{{ failed.name }}</b> <span class="muted">({{ failed.code }})</span></div>
    <div v-else-if="fin">The session ended: {{ fin.outcome }}{{ fin.check ? `, check ${fin.check}` : '' }}{{ fin.code ? ` (${fin.code})` : '' }}</div>
    <div v-else class="muted">The tampered session is running. If it stops and waits, the receiver is still waiting for bytes that never came.</div>
  </div>
</template>
