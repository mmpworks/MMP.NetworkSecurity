<script setup lang="ts">
import { computed, ref } from 'vue'
import { lessons } from '../store'
import ShowKeysSwitch from './ShowKeysSwitch.vue'
import {
  FLOWS, GROUPS, actionFor, chipFor, closeSecurity, flowOf, flowRow, openFlow, sec, setMode, typeRow, useBuiltinEverywhere, words, type KeyMode, type TypeRow,
} from '../security'

const goalLesson = ref<number | null>(null)
const builtLessons = computed(() => lessons.value.filter(l => l.built && l.lesson > 0))
const usedBy = (t: TypeRow) => (t.usedBy.length === 1 ? `Lesson ${t.usedBy[0]}` : `Lessons ${t.usedBy.join(', ')}`)
const rows = (ids: readonly string[]) => ids.map(typeRow).filter((t): t is TypeRow => !!t)
const anyMine = computed(() => sec.types.some(t => t.mode === 'Mine'))

async function chooseMode(t: TypeRow, mode: KeyMode) {
  if (t.mode === mode) return
  const ok = await setMode(t.typeId, mode)
  const now = typeRow(t.typeId)
  // A switch to My test key with no key saved opens the wizard at once (wizards-ux.md 3.5).
  if (ok && mode === 'Mine' && now?.state === 'Unconfigured') await openFlow(flowOf(t.typeId))
}

async function act(t: TypeRow) {
  if (t.mode === 'BuiltIn') return chooseMode(t, 'Mine')
  await openFlow(flowOf(t.typeId))
}

/** The goal card: open the first flow this lesson needs, and come back to the lesson after it. */
async function runWithMine() {
  const n = goalLesson.value
  if (n == null) return
  const needed = FLOWS.filter(f => f.lessons.includes(n as never))
  const next = needed.find(f => f.types.some(id => { const t = typeRow(id); return !t || t.mode !== 'Mine' || t.state !== 'Verified' })) ?? needed[0]
  if (next) await openFlow(next.flowId, n)
}
</script>

<template>
  <section class="sec-page" data-testid="sec-page" aria-label="Security setup">
    <header class="sec-head">
      <h1 class="sec-title">Security setup</h1>
      <v-btn variant="text" prepend-icon="mdi-arrow-left" data-testid="sec-back" @click="closeSecurity">Back to lessons</v-btn>
      <v-spacer />
      <ShowKeysSwitch testid="sec-show-keys-switch" />
    </header>
    <p class="sec-line" data-testid="sec-test-keys-line">{{ sec.showKeys ? words('wizard.common.test-keys-only') : words('wizard.common.test-keys-hidden') }}</p>

    <v-alert v-if="sec.fault" type="error" density="compact" class="mb-3" data-testid="sec-fault"><span data-testid="sec-fault-code">{{ sec.fault.code }}</span> {{ sec.fault.message }}</v-alert>

    <div class="sec-goal" data-testid="sec-goal-card">
      <b>Run a lesson with my own keys</b>
      <select v-model.number="goalLesson" class="ns-select" aria-label="Lesson" data-testid="sec-goal-lesson">
        <option :value="null" disabled>Pick a lesson</option>
        <option v-for="l in builtLessons" :key="l.lesson" :value="l.lesson">Lesson {{ l.lesson }}: {{ l.title }}</option>
      </select>
      <v-btn color="primary" :disabled="goalLesson == null" data-testid="sec-goal-go" @click="runWithMine">Start</v-btn>
    </div>

    <div class="sec-flows" data-testid="sec-flows">
      <v-btn v-for="f in FLOWS" :key="f.flowId" variant="tonal" :data-testid="`flow-${f.flowId}`" @click="openFlow(f.flowId)">
        {{ words(`wizard.flow.${f.flowId}.title`, f.flowId) }}
        <v-chip v-if="flowRow(f.flowId)?.openRunId" size="x-small" class="ml-2" :data-testid="`flow-paused-${f.flowId}`">Setup paused</v-chip>
      </v-btn>
    </div>

    <div class="sec-map" data-testid="sec-map">
      <template v-for="g in GROUPS" :key="g.title">
        <h2 class="sec-group">{{ g.title }}</h2>
        <div v-for="t in rows(g.types)" :key="t.typeId" class="sec-row" :data-testid="`type-row-${t.typeId}`">
          <div class="sec-name">
            <b :data-testid="`type-title-${t.typeId}`">{{ words(`wizard.type.${t.typeId}.title`, t.typeId) }}</b>
            <small class="muted">{{ t.typeId }}</small>
            <span class="muted" :data-testid="`type-why-${t.typeId}`">{{ words(`wizard.type.${t.typeId}.why`) }}</span>
          </div>
          <v-btn-toggle :model-value="t.mode" mandatory density="compact" divided :data-testid="`type-mode-${t.typeId}`" @update:model-value="v => v && chooseMode(t, v)">
            <v-btn value="BuiltIn" size="small" :data-testid="`type-mode-builtin-${t.typeId}`">Built-in key</v-btn>
            <v-btn value="Mine" size="small" :data-testid="`type-mode-mine-${t.typeId}`">My test key</v-btn>
          </v-btn-toggle>
          <v-chip :color="chipFor(t).tone" size="small" :data-testid="`type-state-${t.typeId}`" :data-state="chipFor(t).id">
            <v-icon start size="14">{{ chipFor(t).icon }}</v-icon>{{ chipFor(t).text }}
          </v-chip>
          <span class="muted sec-used" :data-testid="`type-usedby-${t.typeId}`">{{ usedBy(t) }}</span>
          <v-btn size="small" variant="tonal" :data-testid="`type-action-${t.typeId}`" @click="act(t)">{{ actionFor(t) }}</v-btn>
        </div>
      </template>
    </div>

    <footer class="sec-foot">
      <v-btn variant="text" :disabled="!anyMine" data-testid="sec-all-builtin" @click="useBuiltinEverywhere">Use built-in keys everywhere</v-btn>
    </footer>
  </section>
</template>
