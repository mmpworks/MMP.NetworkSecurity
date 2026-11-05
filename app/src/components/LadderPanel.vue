<script setup lang="ts">
import { computed } from 'vue'
import { ladderRungs, registers } from '../lab'
import { allEvents, isReal, selectedEvent } from '../store'

// Lessons 5 and 6: the keys in the order the engine made them. A rung that the engine erased is shown erased. The register count comes from the event.
const upTo = computed(() => selectedEvent.value?.seq ?? Infinity)
const rungs = computed(() => ladderRungs(allEvents.value, upTo.value))
const regs = computed(() => registers(allEvents.value, upTo.value))
const short = (s: string) => s.replace(/^dukpt\./, '')
</script>

<template>
  <div class="ladder" data-testid="key-ladder">
    <div v-if="isReal" class="empty-note">Values are held by the OS. This course shows none of them in real mode.</div>
    <template v-else>
      <div v-if="regs" class="regs" data-testid="reader-registers">Reader registers: <b>{{ regs.held }}</b> held, next counter {{ regs.next }}</div>
      <div v-if="!rungs.length" class="empty-note">Keys appear here as the engine derives them.</div>
      <div v-for="(r, i) in rungs" :key="r.key" class="rung" :class="r.state" :data-testid="`key-rung-${i}`" :data-name="r.name">
        <span class="rname">{{ r.holder }} · {{ short(r.name) }}</span>
        <span v-for="d in r.derivedFrom" :key="d" class="chip-from">from {{ d }}</span>
        <span v-if="r.state === 'erased'" class="erased-tag" :data-testid="`key-rung-erased-${i}`">erased from the {{ r.holder }} memory</span>
      </div>
    </template>
  </div>
</template>
