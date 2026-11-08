<script setup lang="ts">
import { computed, nextTick, onMounted } from 'vue'
import { attackGroups, runCount } from '../attackIndex'
import { lessons, openAttackRun, ui } from '../store'

// The attack index (docs/sections-plan.md item 3). Every run the Host registers, grouped by kind. Each row names the run, its lesson,
// and the check that catches it, and a click plays it in its lesson.
const groups = computed(() => attackGroups(lessons.value))
const total = computed(() => runCount(groups.value))

// Back from a run lands on its row, in view and focused, so the learner keeps their place.
onMounted(async () => {
  if (!ui.attackKept) return
  await nextTick()
  const row = document.querySelector<HTMLElement>(`[data-testid="attack-row-${ui.attackKept}"]`)
  row?.scrollIntoView({ block: 'center' })
  row?.focus()
})
</script>

<template>
  <section class="attack-index" data-testid="attack-index" aria-labelledby="attack-index-title">
    <header class="ai-head">
      <h2 id="attack-index-title">Attack runs</h2>
      <p class="muted" data-testid="attack-index-count">{{ total }} attack runs, grouped by kind. Each one plays in its lesson, beside the check that catches it.</p>
    </header>
    <div v-for="g in groups" :key="g.label.id" class="ai-group" :data-testid="`attack-group-${g.label.id}`">
      <h3 class="ai-group-name">{{ g.label.text }} <span class="muted">{{ g.rows.length }}</span></h3>
      <button
        v-for="r in g.rows" :key="r.attackId" type="button" class="ai-row" :class="{ kept: ui.attackKept === r.attackId }"
        :data-testid="`attack-row-${r.attackId}`" :data-kind="r.kind" :data-lesson="r.lesson" :data-kept="ui.attackKept === r.attackId ? 'true' : undefined"
        @click="openAttackRun(r.lesson, r.attackId)"
      >
        <span class="ai-row-top">
          <span class="ai-row-name" data-testid="attack-row-name">{{ r.name }}</span>
          <span class="ai-row-lesson muted">Lesson {{ r.lesson }}</span>
          <span v-if="r.name !== r.attackId" class="ai-row-id muted" data-testid="attack-row-id">{{ r.attackId }}</span>
        </span>
        <span class="ai-row-check" data-testid="attack-row-check">
          <template v-if="r.check">Caught by: <b>{{ r.check }}</b></template>
          <template v-else>No check catches this run.</template>
        </span>
        <span v-if="r.guard" class="ai-row-guard muted" data-testid="attack-row-guard">{{ r.guard }}</span>
      </button>
    </div>
  </section>
</template>
