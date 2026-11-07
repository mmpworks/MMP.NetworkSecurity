<script setup lang="ts">
import { computed } from 'vue'
import { sectionOf, walkStatus } from '../sections'
import { ui } from '../store'

// The rail of Handshake or Techniques: one item per walk. A walk that is not built yet says it comes later.
const section = computed(() => sectionOf(ui.section))
const picked = computed(() => ui.walkItem[ui.section] ?? null)
function pick(id: string) { ui.walkItem = { ...ui.walkItem, [ui.section]: id } }
</script>

<template>
  <nav class="rail" data-testid="section-rail" :aria-label="section.label">
    <button
      v-for="w in section.items" :key="w.id" type="button" class="rail-item" :class="{ on: picked === w.id }"
      :data-testid="`walk-item-${w.id}`" :aria-current="picked === w.id ? 'true' : undefined" @click="pick(w.id)"
    >
      <span class="rail-body">
        <span class="rail-title" :title="w.label">{{ w.label }}</span>
        <span class="rail-status">{{ walkStatus(w) }}</span>
      </span>
    </button>
  </nav>
</template>
