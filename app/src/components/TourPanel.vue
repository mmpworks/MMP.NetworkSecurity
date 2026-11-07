<script setup lang="ts">
import { computed } from 'vue'
import { LESSON_NOTES, active, doTryIt, lessonRow, startSession, step, steps, tour, tourBack, tourNext, tourReplay, unlock, ui } from '../store'
import { splitText } from '../tour'
import AttackResult from "./AttackResult.vue"
import Term from "./Term.vue"

const paragraphs = computed(() => (step.value?.text ?? []).map(splitText))
const noTour = computed(() => steps.value.length === 0)
const last = computed(() => tour.stepIndex >= steps.value.length - 1)
const canStart = computed(() => !!lessonRow.value?.built && !noTour.value)
const note = computed(() => (ui.lesson != null ? LESSON_NOTES[ui.lesson] ?? '' : ''))
// The button stays after the try-it is done, because a learner can run it again.
const tried = computed(() => !!step.value?.tryIt && unlock.value.open)
</script>

<template>
  <div class="tour" data-testid="tour-panel">
    <div class="tour-head">
      <div class="tour-line"><span class="side-title">TOUR</span><span v-if="tour.active && step" class="muted" data-testid="tour-progress">Step {{ tour.stepIndex + 1 }} of {{ steps.length }}</span></div>
      <div v-if="tour.active && step" class="stepsbar" :style="{ gridTemplateColumns: `repeat(${steps.length}, minmax(0, 1fr))` }" aria-hidden="true" data-testid="tour-steps-bar">
        <i v-for="(_, i) in steps" :key="i" :class="{ done: i < tour.stepIndex, now: i === tour.stepIndex }" />
      </div>
    </div>

    <div v-if="ui.lesson == null" class="empty-note">Pick a lesson on the left to begin.</div>
    <div v-else-if="!lessonRow?.built" class="empty-note">Lesson {{ ui.lesson }} is not built yet. The engine for it comes in a later slice.</div>

    <div v-else-if="!tour.active || !step" class="tour-intro">
      <h3>{{ lessonRow?.title }}</h3>
      <p v-if="noTour" class="muted">This lesson has no tour yet. You can still watch it in free play.</p>
      <p v-else>This tour has {{ steps.length }} steps. The engine waits for you at each one.</p>
      <p v-if="note" class="lesson-note" data-testid="lesson-note">{{ note }}</p>
      <div class="btn-row">
        <v-btn color="primary" variant="flat" :disabled="!canStart || !!active" @click="startSession('tour')">Start tour</v-btn>
        <v-btn :disabled="!lessonRow?.built || !!active" data-testid="start-free-play" @click="startSession('free')">Free play</v-btn>
      </div>
    </div>

    <div v-else class="tour-step">
      <div class="tour-body">
      <div class="muted step-id" data-testid="tour-step-id">{{ step.id }}</div>
      <h3>{{ step.title }}</h3>
      <div data-testid="tour-text">
        <p v-for="(segs, i) in paragraphs" :key="i">
          <template v-for="(s, j) in segs" :key="j"><Term v-if="s.kind === 'term'" :id="s.id" :label="s.text" /><template v-else>{{ s.text }}</template></template>
        </p>
      </div>
      <p v-if="note" class="lesson-note" data-testid="lesson-note">{{ note }}</p>
      <div v-if="step.tryIt" class="tryit" :class="{ done: tried }" data-testid="tour-try-it">
        <div class="side-title">{{ tried ? "DONE" : "TRY IT" }}</div>
        <v-btn color="primary" :variant="tried ? 'outlined' : 'flat'" data-testid="tour-try-it-action" @click="doTryIt">{{ step.tryIt.label }}</v-btn>
      </div>
      <AttackResult />
      </div>
      <div class="tour-foot">
        <v-btn :disabled="tour.stepIndex === 0" data-testid="tour-back" @click="tourBack">Back</v-btn>
        <v-btn data-testid="tour-replay" @click="tourReplay">Replay step</v-btn>
        <div class="next-reason" data-testid="next-reason">{{ unlock.open ? "" : unlock.reason }}</div>
        <v-btn color="primary" variant="flat" :disabled="!unlock.open" data-testid="tour-next" @click="tourNext">{{ last ? "Finish" : "Next" }}</v-btn>
      </div>
    </div>
  </div>
</template>
