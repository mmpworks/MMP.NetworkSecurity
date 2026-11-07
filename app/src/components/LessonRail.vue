<script setup lang="ts">
import { isHighlighted, lessonDone, lessons, selectLesson, ui } from '../store'
import { lessonNeeds, showNeeds } from '../security'
import { TOURS } from '../tour'

function status(n: number, built: boolean): string {
  if (!built) return 'not built yet'
  if (lessonDone(n)) return 'finished'
  return TOURS.has(n) ? 'ready' : 'ready, no tour yet'
}
const needTitle = (n: number) => { const c = lessonNeeds(n).length; return `${c} ${c === 1 ? 'key needs' : 'keys need'} setup` }
</script>

<template>
  <nav class="rail" data-testid="lesson-rail" aria-label="Lessons">
    <button
      v-for="l in lessons" :key="l.lesson" type="button" class="rail-item" :class="{ on: ui.lesson === l.lesson, off: !l.built, hl: isHighlighted('rail', 'lesson', String(l.lesson)) }"
      :data-testid="`lesson-item-${l.lesson}`" :aria-current="ui.lesson === l.lesson ? 'true' : undefined" @click="selectLesson(l.lesson)"
    >
      <span class="rail-num">{{ l.lesson }}</span>
      <span class="rail-body">
        <span class="rail-title" :title="l.title">{{ l.title }}</span>
        <span class="rail-status" :data-testid="`lesson-status-${l.lesson}`">{{ status(l.lesson, l.built) }}</span>
      </span>
      <span
        v-if="lessonNeeds(l.lesson).length" class="rail-keys" role="button" tabindex="0" :title="needTitle(l.lesson)" :aria-label="needTitle(l.lesson)" :data-testid="`lesson-keys-badge-${l.lesson}`"
        @click.stop="showNeeds(l.lesson)" @keydown.enter.stop.prevent="showNeeds(l.lesson)"
      ><v-icon size="14">mdi-key-outline</v-icon></span>
    </button>
  </nav>
</template>
