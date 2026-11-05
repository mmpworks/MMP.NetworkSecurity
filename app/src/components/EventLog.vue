<script setup lang="ts">
import { computed, ref } from 'vue'
import { active, allEvents, attack, isHighlighted, lessonRow, loadTrace, pauseEngine, restartSession, runEngine, selectEvent, selectedEvent, startSession, stepEngine, ui } from '../store'

const actor = ref('')
const type = ref('')
const checksOnly = ref(false)
const traceFile = ref('')
import AttackResult from './AttackResult.vue'
const actors = computed(() => [...new Set(allEvents.value.map(e => e.actor).filter(Boolean))])
const rows = computed(() => allEvents.value.filter(e => (!actor.value || e.actor === actor.value) && (!type.value || e.type.includes(type.value)) && (!checksOnly.value || e.check)))
</script>

<template>
  <div class="tour" data-testid="event-log">
    <div class="inspector-tools"><span class="side-title">FREE PLAY</span><span class="muted">{{ allEvents.length }} events</span></div>
    <div class="btn-row">
      <v-btn v-if="!active" :disabled="ui.lesson == null || !lessonRow?.built" data-testid="free-start" @click="startSession('free')">Start free play</v-btn>
      <v-btn data-testid="free-run" :disabled="!active" @click="runEngine">Run</v-btn>
      <v-btn data-testid="free-pause" :disabled="!active" @click="pauseEngine">Pause</v-btn>
      <v-btn data-testid="free-step" :disabled="!active" @click="stepEngine">Step</v-btn>
      <v-btn data-testid="free-restart" :disabled="ui.lesson == null" @click="restartSession">Restart</v-btn>
    </div>
    <div class="btn-row">
      <select v-model="actor" class="ns-select" data-testid="event-filter-actor" aria-label="Filter by actor"><option value="">all actors</option><option v-for="a in actors" :key="a" :value="a">{{ a }}</option></select>
      <input v-model="type" class="ns-input" placeholder="type contains" data-testid="event-filter-type" aria-label="Filter by type" />
      <label class="muted"><input v-model="checksOnly" type="checkbox" /> checks only</label>
    </div>
    <div class="btn-row">
      <input v-model="traceFile" class="ns-input" placeholder="saved trace file" data-testid="open-trace-path" aria-label="Saved trace file" />
      <v-btn data-testid="open-trace" :disabled="!traceFile" @click="loadTrace(traceFile)">Open saved trace</v-btn>
    </div>
    <div class="btn-row" data-testid="attacks-drawer">
      <span class="side-title">ATTACKS</span>
      <span v-if="!lessonRow?.attacks.length" class="muted">none for this lesson yet</span>
      <v-btn v-for="a in lessonRow?.attacks ?? []" :key="a.attackId" color="error" :disabled="!active" :data-testid="`attack-${a.attackId}`" @click="attack({ attackId: a.attackId })">{{ a.label }}</v-btn>
    </div>
    <AttackResult />
    <div class="log-rows">
      <div
        v-for="e in rows" :key="e.seq" class="log-row" :class="{ sel: selectedEvent?.seq === e.seq, fail: e.check?.result === 'fail' }"
        :data-testid="`event-row-${e.seq}`" tabindex="0" @click="selectEvent(e.seq)" @keydown.enter="selectEvent(e.seq)"
      >
        <span class="muted">{{ e.seq }}</span><span>{{ e.actor }}</span><span>{{ e.type }}</span><span v-if="e.check" :class="[e.check.result === 'fail' ? 'chk-fail-t' : 'chk-pass-t', { hl: isHighlighted('check', 'name', e.check.name) }]">{{ e.check.result === 'fail' ? '✕' : '✓' }} {{ e.check.name }}</span>
      </div>
    </div>
  </div>
</template>
