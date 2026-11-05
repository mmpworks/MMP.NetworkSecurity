<script setup lang="ts">
import { lessonDone, lessons, selectLesson, ui } from '../store'
import { TOURS } from '../tour'

function status(n: number, built: boolean): string {
  if (!built) return 'not built yet'
  if (lessonDone(n)) return 'finished'
  return TOURS.has(n) ? 'ready' : 'ready, no tour yet'
}
</script>

<template>
  <nav class="rail" data-testid="lesson-rail" aria-label="Lessons">
    <button
      v-for="l in lessons" :key="l.lesson" type="button" class="rail-item" :class="{ on: ui.lesson === l.lesson, off: !l.built }"
      :data-testid="`lesson-item-${l.lesson}`" :aria-current="ui.lesson === l.lesson ? 'true' : undefined" @click="selectLesson(l.lesson)"
    >
      <span class="rail-num">{{ l.lesson }}</span>
      <span class="rail-body">
        <span class="rail-title">{{ l.title }}</span>
        <span class="rail-status" :data-testid="`lesson-status-${l.lesson}`">{{ status(l.lesson, l.built) }}</span>
      </span>
    </button>
  </nav>
</template>
