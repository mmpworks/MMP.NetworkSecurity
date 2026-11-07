<script setup lang="ts">
import { computed } from 'vue'
import TextWithSpecs from './TextWithSpecs.vue'
import { timingOf, type TimingCase } from '../lab'
import { allEvents, upToSeq } from '../store'

// Lesson 11: the numbers the native lab measured. Every figure here comes from a timing.* event. The panel states what the run measured and no more.
const t = computed(() => timingOf(allEvents.value, upToSeq.value))
const fmt = (n: number | null | undefined, d = 1) => (n == null ? 'infinite' : Number(n).toFixed(d))
const bars = (c: TimingCase) => { const max = Math.max(1, ...c.histogram.map(h => h.count)); return c.histogram.map(h => ({ ns: h.ns, count: h.count, h: Math.round((h.count / max) * 48) })) }
const label = (c: TimingCase) => `${c.compare}, differs at byte ${c.diffPosition + 1} of ${c.bufferSize}`
</script>

<template>
  <div class="timing" data-testid="timing-panel">
    <div v-if="t.failed" class="attack-result" data-testid="timing-failed">The lab stopped at {{ t.failed.check?.name || t.failed.type }}: <TextWithSpecs :text="t.failed.message" /><span v-if="t.failed.check" class="muted"> ({{ t.failed.check.code }})</span></div>
    <div v-if="t.machine" class="muted" data-testid="timing-machine">This machine: CLR {{ t.machine.clr }}, {{ t.machine.pointerBytes * 8 }}-bit.</div>
    <div v-if="!t.cases.length && !t.verdict && !t.guesses.length && !t.failed" class="empty-note">The lab has not measured anything yet.</div>

    <div v-for="m in t.cases" :key="m.e.seq" class="measure-card" :data-testid="`timing-case-${m.c.compare}-${m.c.diffPosition === 0 ? 'first' : 'last'}`">
      <div class="side-title">{{ label(m.c) }}</div>
      <svg class="hist" viewBox="0 0 220 52" role="img" :aria-label="`Timing histogram, ${m.c.samples} samples`">
        <rect v-for="(b, i) in bars(m.c)" :key="i" :x="i * (220 / Math.max(1, m.c.histogram.length))" :y="52 - b.h" :width="Math.max(1, 220 / Math.max(1, m.c.histogram.length) - 1)" :height="b.h" class="hbar" :class="{ leak: m.c.compare === 'leaky' }" />
      </svg>
      <div class="muted">{{ m.c.samples }} samples. Mean {{ fmt(m.c.meanNs) }} ns, median {{ fmt(m.c.medianNs, 0) }} ns, 99th percentile {{ fmt(m.c.p99Ns, 0) }} ns.</div>
    </div>

    <div v-for="m in t.managed" :key="m.e.seq" class="measure-card" data-testid="timing-managed">
      <div class="side-title">MANAGED CODE · {{ m.e.message }}</div>
      <div class="muted">{{ m.c.samples }} samples. Mean {{ fmt(m.c.meanNs) }} ns, median {{ fmt(m.c.medianNs, 0) }} ns.</div>
    </div>

    <div v-if="t.verdict" class="measure-card" data-testid="timing-verdict">
      <div class="side-title">WHAT THIS RUN MEASURED</div>
      <div class="crow"><span>leaky compare, |t|</span><code data-testid="t-leaky">{{ fmt(t.verdict.v.leakyT === null ? null : Math.abs(t.verdict.v.leakyT), 2) }}</code></div>
      <div class="crow"><span>constant-time compare, |t|</span><code data-testid="t-constant">{{ fmt(t.verdict.v.constantTimeT === null ? null : Math.abs(t.verdict.v.constantTimeT), 2) }}</code></div>
      <div class="crow"><span>constant-time against itself (this machine's noise), |t|</span><code data-testid="t-control">{{ fmt(t.verdict.v.controlT === null ? null : Math.abs(t.verdict.v.controlT), 2) }}</code></div>
      <div class="crow"><span>managed compare, |t|</span><code data-testid="t-managed">{{ fmt(t.verdict.v.managedT === null ? null : Math.abs(t.verdict.v.managedT), 2) }}</code></div>
      <div class="muted" data-testid="timing-separated">{{ t.verdict.v.separated ? 'The leaky compare separates from the others in this run.' : 'The leaky compare did not separate in this run. This machine may be too noisy. Run again.' }}</div>
    </div>

    <div v-for="m in t.guesses" :key="m.e.seq" class="measure-card" :data-testid="`timing-guess-${m.g.compare}`">
      <div class="side-title">GUESS LOOP · {{ m.g.compare }}</div>
      <div data-testid="guess-result"><b>{{ m.g.correctBytes }}</b> of {{ m.g.totalBytes }} secret bytes found, {{ m.g.samplesPerGuess }} samples per candidate.</div>
      <div class="guess-bytes"><span v-for="(b, i) in m.g.bytes" :key="i" class="gb" :title="`margin ${fmt(b.marginNs)} ns`">{{ b.value.toString(16).padStart(2, '0') }}</span></div>
    </div>
  </div>
</template>
