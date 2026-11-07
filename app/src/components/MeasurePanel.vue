<script setup lang="ts">
import { computed } from 'vue'
import { avalancheOf, listenerCanMeasure, parseDetail, percent } from '../lab'
import { selectedEvent, shownEvents, ui, upToSeq } from '../store'

// Numbers come from measure.result events and nothing else (ux-design.md: no fake data).
const upTo = upToSeq
const eve = computed(() => ui.view === 'eavesdropper')
const measures = computed(() => shownEvents.value.filter(e => e.type === 'measure.result' && e.seq <= upTo.value && (!eve.value || listenerCanMeasure(e))).map(e => ({ e, d: parseDetail(e.detail), av: e.message.includes('avalanche') ? avalancheOf(e.plain) : null })))
</script>

<template>
  <div class="measures" data-testid="measure-panel">
    <div v-if="!measures.length" class="empty-note" data-testid="measure-none">{{ eve ? 'These numbers come from inside an endpoint, so a listener cannot take them.' : 'Measurements appear here when the lab takes one.' }}</div>
    <div v-for="m in measures" :key="m.e.seq" class="measure-card" :data-testid="`measure-${m.e.message}`">
      <div class="side-title">{{ eve && m.d.blocks ? 'A locked message' : m.e.message }}</div>
      <template v-if="m.av">
        <div class="avalanche" data-testid="avalanche-grid" role="img" :aria-label="`${m.av.count} of 256 bits changed`">
          <span v-for="(f, i) in m.av.flipped" :key="i" class="abit" :class="{ on: f }" />
        </div>
        <div data-testid="avalanche-count"><b>{{ m.av.count }}</b> of 256 bits changed ({{ percent(m.av.count, 256) }}%) after one flipped input bit<span v-if="m.d.bits && Number(m.d.bits) !== m.av.count" class="muted"> (the engine reports {{ m.d.bits }})</span></div>
      </template>
      <template v-else-if="m.d.blocks">
        <div class="bar" role="img" :aria-label="`${m.d.repeats} of ${m.d.blocks} blocks repeat`"><div class="bar-fill" :style="{ width: percent(Number(m.d.repeats), Number(m.d.blocks)) + '%' }" /></div>
        <div>{{ m.d.repeats }} of {{ m.d.blocks }} locked blocks repeat an earlier block</div>
      </template>
      <div v-else class="muted">{{ m.e.detail }}</div>
    </div>
  </div>
</template>
