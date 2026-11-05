<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { HEAD_H, ROW_H, layoutDiagram, protocolOf } from '../layout'
import { isHighlighted, lessonRow, replayTick, selectEvent, selectedEvent, shownEvents, ui } from '../store'
import type { ViewMode } from '../types'

const props = defineProps<{ view: Exclude<ViewMode, 'both'>; inLightbox?: boolean; protocol?: string }>()
const emit = defineEmits<{ (e: 'lightbox'): void }>()

// `protocol` keeps only the events of one stream family (lesson 7 draws TLS 1.1 and TLS 1.3 side by side).
const events = computed(() => (props.protocol ? shownEvents.value.filter(e => protocolOf(e) === props.protocol) : shownEvents.value))
const layout = computed(() => layoutDiagram(events.value, lessonRow.value?.lanes ?? [], props.view))
const zoom = ref(1)
const box = ref<HTMLElement | null>(null)
const reduced = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches

const clamp = (z: number) => Math.min(4, Math.max(0.25, z))
const zoomIn = () => { zoom.value = clamp(zoom.value * 1.25) }
const zoomOut = () => { zoom.value = clamp(zoom.value / 1.25) }
const zoomFit = () => {
  const w = box.value?.clientWidth ?? layout.value.width
  zoom.value = clamp(Math.min(1, w / Math.max(1, layout.value.width)))
}

function onKey(ev: KeyboardEvent) {
  if (ev.key === '+' || ev.key === '=') { zoomIn(); ev.preventDefault() }
  else if (ev.key === '-') { zoomOut(); ev.preventDefault() }
  else if (ev.key === '0') { zoomFit(); ev.preventDefault() }
  else if (ev.shiftKey && box.value && ev.key.startsWith('Arrow')) {
    const d = 60
    if (ev.key === 'ArrowLeft') box.value.scrollLeft -= d
    if (ev.key === 'ArrowRight') box.value.scrollLeft += d
    if (ev.key === 'ArrowUp') box.value.scrollTop -= d
    if (ev.key === 'ArrowDown') box.value.scrollTop += d
    ev.preventDefault()
  }
}
function onWheel(ev: WheelEvent) {
  if (!ev.ctrlKey) return
  ev.preventDefault()
  if (ev.deltaY < 0) zoomIn(); else zoomOut()
}

// Follow the newest event until the learner scrolls away or presses Follow.
watch(() => layout.value.rows.length, async () => {
  if (!ui.follow || !box.value) return
  await nextTick()
  box.value.scrollTop = box.value.scrollHeight
})
function onScroll() {
  const b = box.value
  if (!b) return
  ui.follow = b.scrollTop + b.clientHeight >= b.scrollHeight - 8
}
function follow() { ui.follow = true; if (box.value) box.value.scrollTop = box.value.scrollHeight }

const last = computed(() => layout.value.rows[layout.value.rows.length - 1] ?? null)
const dur = computed(() => `${(0.6 / ui.speed).toFixed(2)}s`)
const waitingLane = computed(() => {
  const e = shownEvents.value[shownEvents.value.length - 1]
  return e?.waiting ? layout.value.lanes.find(l => l.name === e.waiting.toLowerCase()) ?? null : null
})
const announce = computed(() => {
  const r = last.value
  return r ? `${r.label}, ${r.bytes} bytes` : ''
})
const arrowEnd = (r: { fromX: number; toX: number }) => (r.toX >= r.fromX ? r.toX - 8 : r.toX + 8)
const mid = (r: { fromX: number; toX: number }) => (r.fromX + r.toX) / 2
const pulse = computed(() => replayTick.value)
</script>

<template>
  <div class="diagram" :data-testid="inLightbox ? 'diagram-lightbox' : 'diagram'" tabindex="0" role="img" aria-label="Sequence diagram of the session" @keydown="onKey">
    <div class="diagram-tools">
      <v-btn size="x-small" icon="mdi-magnify-minus-outline" aria-label="Zoom out" data-testid="diagram-zoom-out" @click="zoomOut" />
      <span class="muted">{{ Math.round(zoom * 100) }}%</span>
      <v-btn size="x-small" icon="mdi-magnify-plus-outline" aria-label="Zoom in" data-testid="diagram-zoom-in" @click="zoomIn" />
      <v-btn size="x-small" icon="mdi-fit-to-screen-outline" aria-label="Fit" data-testid="diagram-zoom-fit" @click="zoomFit" />
      <v-btn v-if="!ui.follow" size="x-small" data-testid="diagram-follow" @click="follow">Follow</v-btn>
      <v-btn v-if="!inLightbox" size="x-small" icon="mdi-arrow-expand-all" aria-label="Open in a full window" data-testid="diagram-expand" @click="emit('lightbox')" />
      <span v-if="view === 'eavesdropper'" class="eve-count" data-testid="eve-count">The eavesdropper read {{ layout.learned }} of {{ layout.total }} messages</span>
    </div>
    <div ref="box" class="diagram-scroll" @wheel="onWheel" @scroll="onScroll">
      <svg :width="layout.width * zoom" :height="layout.height * zoom" :viewBox="`0 0 ${layout.width} ${layout.height}`" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern id="hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><line x1="0" y1="0" x2="0" y2="6" class="hatch-line" /></pattern>
          <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="context-stroke" /></marker>
        </defs>
        <g v-for="l in layout.lanes" :key="l.name" :data-testid="`diagram-lane-${l.name}`" :class="{ hl: isHighlighted('diagram', 'lane', l.name) }">
          <rect :x="l.x - 70" y="8" width="140" height="34" rx="8" class="lane-head" />
          <text :x="l.x" y="30" text-anchor="middle" class="lane-name">{{ l.name }}</text>
          <line :x1="l.x" :x2="l.x" :y1="HEAD_H" :y2="layout.height" class="lane-line" />
        </g>
        <circle v-if="waitingLane" :cx="waitingLane.x" :cy="HEAD_H + 12" r="9" class="wait-ring" data-testid="engine-waiting-ring" />
        <g v-for="r in layout.rows.filter(x => x.kind === 'divider')" :key="r.seq" class="divider-row">
          <line :x1="20" :x2="layout.width - 20" :y1="r.y" :y2="r.y" class="divider-line" />
          <text :x="layout.width / 2" :y="r.y - 6" text-anchor="middle" class="divider-text" data-testid="round-divider">{{ r.label }}</text>
        </g>
        <g v-for="r in layout.rows.filter(x => x.kind !== 'divider')" :key="r.seq" class="row" :class="{ sel: selectedEvent?.seq === r.seq, hl: isHighlighted('diagram', 'message', r.label) }" :data-testid="`diagram-message-${r.seq}`" @click="selectEvent(r.seq)">
          <rect x="0" :y="r.y - ROW_H / 2 + 6" :width="layout.width" :height="ROW_H - 8" class="row-band" />
          <template v-if="r.kind === 'arrow'">
            <line :x1="r.fromX" :x2="arrowEnd(r)" :y1="r.y" :y2="r.y" class="arrow" :class="r.protectedBytes ? 'enc' : 'readable'" marker-end="url(#arr)" />
            <text :x="mid(r)" :y="r.y - 9" text-anchor="middle" class="arrow-label" :class="{ unreadable: r.unreadable }">{{ r.label }}</text>
            <text :x="mid(r)" :y="r.y + 16" text-anchor="middle" class="arrow-sub">{{ r.hop ? r.hop + ', ' : '' }}{{ r.bytes }} bytes{{ r.protectedBytes ? ', encrypted' : '' }}</text>
          </template>
          <template v-else>
            <rect :x="r.fromX - 90" :y="r.y - 14" width="180" height="28" rx="6" class="note" :class="r.kind === 'note' ? 'enc-note' : ''" />
            <text :x="r.fromX" :y="r.y + 5" text-anchor="middle" class="arrow-label">{{ r.label }}</text>
          </template>
          <g v-if="r.check" :data-testid="`diagram-check-${r.seq}`" :class="r.check.result === 'fail' ? 'chk-fail' : 'chk-pass'">
            <circle :cx="r.kind === 'arrow' ? r.toX : r.fromX + 104" :cy="r.y" r="11" :data-testid="r.check.result === 'fail' ? 'check-fail-badge' : 'check-pass-badge'" />
            <text :x="r.kind === 'arrow' ? r.toX : r.fromX + 104" :y="r.y + 5" text-anchor="middle" class="chk-mark">{{ r.check.result === 'fail' ? '✕' : '✓' }}</text>
            <text :x="(r.kind === 'arrow' ? r.toX : r.fromX + 104) + 16" :y="r.y + 4" class="chk-name" :class="{ hl: isHighlighted('check', 'name', r.check.name) }" data-testid="check-name">{{ r.check.name }}</text>
          </g>
        </g>
        <!-- The packet chip rides the newest arrow. It shows the first 8 bytes of that event's wire hex. -->
        <g v-if="last && last.kind === 'arrow' && !reduced && ui.viewUpTo === null" :key="`${last.seq}-${pulse}`" class="chip">
          <rect :x="last.fromX" :y="last.y - 11" width="86" height="22" rx="5" :class="last.protectedBytes ? 'chip-enc' : 'chip-read'">
            <animate attributeName="x" :from="last.fromX" :to="last.toX - 43" :dur="dur" fill="freeze" />
          </rect>
          <text :x="last.fromX + 43" :y="last.y + 4" text-anchor="middle" class="chip-text">{{ last.head.slice(0, 8) }}
            <animate attributeName="x" :from="last.fromX + 43" :to="last.toX" :dur="dur" fill="freeze" />
          </text>
        </g>
      </svg>
    </div>
    <div class="sr-only" aria-live="polite" data-testid="diagram-live">{{ announce }}</div>
  </div>
</template>
