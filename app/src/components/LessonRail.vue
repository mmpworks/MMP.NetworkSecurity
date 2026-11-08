<script setup lang="ts">
import { computed } from 'vue'
import { attackGroups, runCount } from '../attackIndex'
import { isHighlighted, lessonDone, lessons, selectLesson, showAttackIndex, ui } from '../store'
import { lessonNeeds, showNeeds } from '../security'
import { TOURS } from '../tour'

function status(n: number, built: boolean): string {
  if (!built) return 'not built yet'
  if (lessonDone(n)) return 'finished'
  return TOURS.has(n) ? 'ready' : 'ready, no tour yet'
}
const needTitle = (n: number) => { const c = lessonNeeds(n).length; return `${c} ${c === 1 ? 'key needs' : 'keys need'} setup` }
const attackTotal = computed(() => runCount(attackGroups(lessons.value)))
/** A lesson pick leaves the attack index, and forgets the kept row, because this lesson was not opened from the index. */
function pick(n: number) {
  showAttackIndex(false)
  ui.attackKept = ''
  ui.twoRun = null
  selectLesson(n)
}
</script>

<template>
  <nav class="rail" data-testid="lesson-rail" aria-label="Lessons">
    <!-- The attack index (sections-plan item 3): every attack run of every lesson, by kind. -->
    <button
      type="button" class="rail-item rail-attacks" :class="{ on: ui.attackIndex }" data-testid="attack-index-open"
      :aria-current="ui.attackIndex ? 'true' : undefined" @click="showAttackIndex(true)"
    >
      <span class="rail-num"><v-icon size="16">mdi-shield-alert-outline</v-icon></span>
      <span class="rail-body">
        <span class="rail-title">Attack runs</span>
        <span class="rail-status">{{ attackTotal }} runs, by kind</span>
      </span>
    </button>
    <button
      v-for="l in lessons" :key="l.lesson" type="button" class="rail-item" :class="{ on: ui.lesson === l.lesson && !ui.attackIndex, off: !l.built, hl: isHighlighted('rail', 'lesson', String(l.lesson)) }"
      :data-testid="`lesson-item-${l.lesson}`" :aria-current="ui.lesson === l.lesson && !ui.attackIndex ? 'true' : undefined" @click="pick(l.lesson)"
      :aria-label="`Lesson ${l.lesson}, ${l.title}, ${status(l.lesson, l.built)}`"
    >
      <span class="rail-num">{{ l.lesson }}</span>
      <span class="rail-body">
        <span class="rail-title" :title="`${l.title}: ${status(l.lesson, l.built)}`">{{ l.title }}</span>
        <span class="rail-status" :data-testid="`lesson-status-${l.lesson}`">{{ status(l.lesson, l.built) }}</span>
      </span>
      <span
        v-if="lessonNeeds(l.lesson).length" class="rail-keys" role="button" tabindex="0" :title="needTitle(l.lesson)" :aria-label="needTitle(l.lesson)" :data-testid="`lesson-keys-badge-${l.lesson}`"
        @click.stop="showNeeds(l.lesson)" @keydown.enter.stop.prevent="showNeeds(l.lesson)"
      ><v-icon size="14">mdi-key-outline</v-icon></span>
    </button>
  </nav>
</template>
