<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { lessons, showAttackIndex, ui } from '../store'
import { changedBytes, checkResult, firstChange, isWire, pairing, splitAt, streamKey, wireSteps } from '../twoRun'
import type { TraceEvent } from '../types'
import SequenceDiagram from './SequenceDiagram.vue'

// The two-run layout (docs/sections-plan.md item 3; Steve, Q4 A): the normal run beside the attacked run, on one clock, paired event
// by event. The changed message shows with its changed bytes lit, and the check that catches the attack shows under each run.
const props = defineProps<{ normalId: string; attackedId: string; attackId: string }>()

const recOf = (id: string) => ui.sessions.find(s => s.id === id) ?? null
const runOf = (id: string): readonly TraceEvent[] => recOf(id)?.events ?? []
const normal = computed(() => runOf(props.normalId))
const attacked = computed(() => runOf(props.attackedId))
// Where the runs part and what changed are read only once both runs have finished: while one still runs, its missing events would
// look like a split that is not there.
const done = computed(() => !!recOf(props.normalId)?.finished && !!recOf(props.attackedId)?.finished)
const paired = computed(() => pairing(normal.value, attacked.value))
const pairs = computed(() => paired.value.pairs)
// A run that holds one key twice cannot pair by stream. The screen says so and shows no split or change, which would be a guess.
const unpaired = computed(() => paired.value.duplicates.length > 0)
const run = computed(() => lessons.value.flatMap(l => l.attacks.map(a => ({ ...a, lesson: l.lesson }))).find(a => a.attackId === props.attackId) ?? null)
const checkName = computed(() => run.value?.expectCheck ?? '')

// One clock for both runs: the step is a pair index, and each run shows its events up to that pair. It follows the newest pair until
// the learner moves it.
const step = ref(0)
const following = ref(true)
watch(() => pairs.value.length, n => { if (following.value) step.value = n }, { immediate: true })
function move(to: number) { following.value = to >= pairs.value.length; step.value = Math.max(0, Math.min(pairs.value.length, to)) }

const indexOf = computed(() => new Map(pairs.value.map((p, i) => [p.key, i])))
/**
 * The step an event shows at. An engine event shows at its own pair. A wire event shows with its side's nearest engine event
 * (wireSteps): '' is the start of the run, and a wire event with no step, or an event with no stream, shows only at the end.
 */
function stepOf(e: TraceEvent, wireAt: Map<TraceEvent, string>): number {
  if (!e.streamId) return Infinity
  if (!isWire(e)) return indexOf.value.get(streamKey(e)) ?? Infinity
  const at = wireAt.get(e)
  return at === undefined ? Infinity : at === '' ? -1 : (indexOf.value.get(at) ?? Infinity)
}
/** A run's events up to the clock. At the last step every event shows. */
function upTo(events: readonly TraceEvent[]): TraceEvent[] {
  if (step.value >= pairs.value.length) return [...events]
  const wireAt = wireSteps(events)
  return events.filter(e => stepOf(e, wireAt) < step.value)
}
const normalShown = computed(() => upTo(normal.value))
const attackedShown = computed(() => upTo(attacked.value))

const normalCheck = computed(() => checkResult(normal.value, checkName.value))
const attackedCheck = computed(() => checkResult(attacked.value, checkName.value))

const readable = computed(() => done.value && !unpaired.value)
const split = computed(() => { const i = readable.value ? splitAt(pairs.value) : -1; return i >= 0 ? { index: i, pair: pairs.value[i] } : null })
// A byte change counts only before the runs part: after a scenario attack parts them, every later message differs, and that is not
// a change the attack made inside one message.
const change = computed(() => {
  const i = readable.value ? firstChange(paired.value.wires) : -1
  if (i < 0) return null
  const pair = paired.value.wires[i]
  const index = pair.at === '' ? 0 : (indexOf.value.get(pair.at) ?? pairs.value.length - 1)
  return !split.value || index < split.value.index ? { index, pair } : null
})
const changed = computed(() => (change.value ? new Set(changedBytes(change.value.pair.normal!.wire, change.value.pair.attacked!.wire)) : new Set<number>()))

const bytesOf = (hex: string) => Array.from({ length: hex.length >> 1 }, (_, i) => hex.slice(2 * i, 2 * i + 2))
const checkWords = (r: 'pass' | 'fail' | 'none') => (r === 'pass' ? 'passes' : r === 'fail' ? 'fails' : 'does not run')
/**
 * What a run does at a pair, in words: a message it sends, or a check it runs. A run with no event at the pair has no more events of
 * that side here. It can still go on on the other side, so the words name the side and never say the run stopped (Richard on #297).
 */
function doing(e: TraceEvent | null, key: string): string {
  if (!e) return `has no more ${key.split('/')[0]} events here`
  if (e.check) return `runs the ${e.check.name} check`
  return `sends ${e.message || e.type}`
}
const label = (e: TraceEvent | null) => (e ? e.message || e.type : '')
</script>

<template>
  <section class="two-run" data-testid="two-run" aria-labelledby="two-run-title">
    <header class="tr-head">
      <v-btn variant="text" prepend-icon="mdi-arrow-left" data-testid="two-run-back" @click="showAttackIndex(true)">Attack runs</v-btn>
      <h2 id="two-run-title">{{ attackId }}</h2>
      <span class="muted">Lesson {{ run?.lesson }}: the normal run beside the attacked run</span>
    </header>

    <div class="tr-clock">
      <v-btn size="small" :disabled="step === 0" data-testid="two-run-prev" @click="move(step - 1)">Back</v-btn>
      <input type="range" min="0" :max="pairs.length" :value="step" aria-label="Step through both runs" data-testid="two-run-clock" @input="move(Number(($event.target as HTMLInputElement).value))" />
      <v-btn size="small" :disabled="step >= pairs.length" data-testid="two-run-next" @click="move(step + 1)">Next</v-btn>
      <span class="muted" data-testid="two-run-step" title="One step is one place in one stream. Both runs move together.">Step {{ step }} of {{ pairs.length }}</span>
    </div>
    <p v-if="unpaired" class="tr-split" data-testid="two-run-unpaired" :data-count="paired.duplicates.length">
      These runs cannot pair by stream: a run sends 2 events at one place in one stream. The panes show both runs, with no split line.
    </p>
    <p v-else-if="split" class="tr-split" data-testid="two-run-split" :data-at="split.index">
      The runs part at step {{ split.index + 1 }}: the normal run {{ doing(split.pair.normal, split.pair.key) }}, and the attacked run {{ doing(split.pair.attacked, split.pair.key) }}.
    </p>
    <p v-else-if="!done" class="muted tr-wait" data-testid="two-run-running">Both runs are still running. Where they part shows when both have finished.</p>

    <div class="tr-panes">
      <div class="tr-pane" data-testid="two-run-normal">
        <h3>The normal run</h3>
        <div class="tr-diagram"><SequenceDiagram view="endpoints" :run-events="normalShown" /></div>
        <p class="tr-check" data-testid="two-run-check-normal" :data-result="normalCheck">
          <template v-if="checkName"><b>{{ checkName }}</b> {{ checkWords(normalCheck) }}.</template>
          <template v-else>The normal run has no attack to catch.</template>
        </p>
      </div>
      <div class="tr-pane tr-pane-attacked" data-testid="two-run-attacked">
        <h3>The attacked run</h3>
        <div class="tr-diagram"><SequenceDiagram view="endpoints" :run-events="attackedShown" /></div>
        <p class="tr-check" data-testid="two-run-check-attacked" :data-result="attackedCheck">
          <template v-if="checkName"><b>{{ checkName }}</b> {{ checkWords(attackedCheck) }}.</template>
          <template v-else>No check catches this attack, so the changed run goes on.</template>
        </p>
      </div>
    </div>

    <div class="tr-diff" data-testid="two-run-diff">
      <template v-if="change">
        <h3>The changed message: {{ label(change.pair.attacked) }}, step {{ change.index + 1 }}</h3>
        <p class="muted">{{ changed.size }} {{ changed.size === 1 ? 'byte differs' : 'bytes differ' }}. The lit bytes are the ones the attack changed.</p>
        <div class="tr-bytes"><span class="tr-row-name muted">normal</span><span v-for="(b, i) in bytesOf(change.pair.normal!.wire)" :key="i" class="tr-byte" :class="{ on: changed.has(i) }">{{ b }}</span></div>
        <div class="tr-bytes"><span class="tr-row-name muted">attacked</span><span v-for="(b, i) in bytesOf(change.pair.attacked!.wire)" :key="i" class="tr-byte" :class="{ on: changed.has(i) }" :data-changed="changed.has(i) ? 'true' : undefined">{{ b }}</span></div>
      </template>
      <p v-else-if="done" class="muted">The attack changed no bytes inside a message. It changed how the run went: see where the runs part.</p>
      <p v-else class="muted">The changed message shows when both runs have finished.</p>
    </div>
  </section>
</template>
