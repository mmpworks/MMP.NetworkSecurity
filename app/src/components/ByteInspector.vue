<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { bytesView } from '../bytes'
import { h2, isProtected } from '../layout'
import { fieldKey, flipSelectedByte, isHighlighted, isOsTransport, replayTick, selectedEvent, toggleField, ui } from '../store'
import type { TraceField } from '../types'
import HexGrid from './HexGrid.vue'

// The Message bytes panel. Before: the readable bytes the sender wrote. After: the bytes on the wire.
// Each field is a toggle. Nothing is lit until the learner picks a field, and a field lights only its own bytes.
const ev = computed(() => selectedEvent.value)
const eve = computed(() => ui.view === 'eavesdropper')
const view = computed(() => (ev.value ? bytesView(ev.value, ui.view) : null))
const fields = computed(() => view.value?.fields ?? [])
const fieldHex = computed(() => (view.value?.fieldsOn === 'before' ? view.value.before?.hex : view.value?.after?.hex) ?? '')
// Without wire bytes the readable grid is the only grid, so its bytes carry the `inspector-byte-<offset>` ids.
const beforeId = computed(() => (view.value?.after ? 'inspector-plain-byte' : 'inspector-byte'))
const locked = computed(() => !!ev.value && isProtected(ev.value))
const unreadableBytes = computed(() => (eve.value ? (ev.value?.fields ?? []).filter(f => !f.visibleToWire).reduce((n, f) => n + f.length, 0) : 0))
const beforeOpen = ref(true)

// A new message starts with nothing lit.
watch(() => [ev.value?.seq, ev.value?.sessionId], () => { ui.litFields = [] })

const isLit = (f: TraceField) => ui.litFields.includes(fieldKey(f))
const readable = (f: TraceField) => !eve.value || f.visibleToWire
const litAt = (off: number) => fields.value.find(f => isLit(f) && off >= f.offset && off < f.offset + f.length) ?? null
const litClassOf = (f: TraceField | null) => (f ? `k-${f.kind}` : '')
// A field on the wire that holds the readable bytes also lights them in the Before grid: this text became these bytes.
function beforeLit(off: number): string {
  const v = view.value
  if (!v) return ''
  if (v.fieldsOn === 'before' || !v.after) return litClassOf(litAt(off))
  return v.source ? litClassOf(litAt(v.source.offset + off)) : ''
}
const afterLit = (off: number) => (view.value?.fieldsOn === 'after' ? litClassOf(litAt(off)) : '')
const marks = computed(() => new Map(fields.value.map(f => [f.offset, f.name])))

// ---- the scramble: the wire bytes settle from noise into the ciphertext (moment 1) ----
const morph = ref(1)
const tick = ref(0)
let timer: ReturnType<typeof setInterval> | null = null
const reduced = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches
function playScramble() {
  if (timer) clearInterval(timer)
  morph.value = 1
  if (reduced || !ev.value || !locked.value || ui.viewUpTo !== null && ui.viewUpTo < 0) return
  morph.value = 0
  const stepMs = 40
  const total = 700 / ui.speed
  timer = setInterval(() => {
    tick.value++
    morph.value = Math.min(1, morph.value + stepMs / total)
    if (morph.value >= 1 && timer) { clearInterval(timer); timer = null }
  }, stepMs)
}
watch(() => [ev.value?.seq, ev.value?.sessionId, replayTick.value], playScramble, { immediate: true })
onBeforeUnmount(() => { if (timer) clearInterval(timer) })
const afterLen = computed(() => (view.value?.after?.hex.length ?? 0) >> 1)
const scramble = computed(() => (morph.value < 1 ? (i: number) => (i / Math.max(1, afterLen.value) < morph.value ? null : h2((i * 131 + tick.value * 17) & 0xff)) : null))

const hiddenAt = (off: number) => (ev.value?.fields ?? []).some(f => !f.visibleToWire && off >= f.offset && off < f.offset + f.length)
const decoded = (f: TraceField) => { const h = fieldHex.value.slice(f.offset * 2, (f.offset + Math.min(f.length, 12)) * 2); return f.length > 12 ? `${h}…` : h }
const where = (f: TraceField) => (f.length === 1 ? `byte ${f.offset}` : `bytes ${f.offset} to ${f.offset + f.length - 1}`)
const pick = (off: number) => { ui.selectedByte = off }
const canFlip = computed(() => ui.selectedByte != null && !!ev.value?.wire && !isOsTransport.value)
</script>

<template>
  <div class="inspector" data-testid="inspector">
    <div class="inspector-tools">
      <span class="side-title" data-testid="inspector-title">MESSAGE BYTES</span>
      <span v-if="ev" class="muted">{{ ev.message || ev.type }}</span>
      <v-spacer />
      <v-btn size="x-small" color="error" :disabled="!canFlip" data-testid="flip-byte-button" @click="flipSelectedByte">Flip this byte</v-btn>
    </div>
    <div v-if="!ev || !view || (!view.before && !view.after && !view.beforeHidden)" class="empty-note">{{ ev ? 'This event moves no bytes.' : 'Bytes appear here when the engine sends a message.' }}</div>
    <div v-else class="inspector-body">
      <div class="byte-grids">
        <section v-if="view.before" class="grid-sec" :class="{ shut: !beforeOpen }">
          <button
            type="button" class="grid-head" :class="{ hl: isHighlighted('inspector', 'toggle', 'wire-plain') }" :aria-expanded="beforeOpen"
            data-testid="inspector-toggle-wire-plain" @click="beforeOpen = !beforeOpen"
          >
            <span class="gh-title readable-t">{{ view.after ? 'Before: what the sender wrote' : 'The bytes' }}</span>
            <span class="muted" data-testid="inspector-before-count">{{ view.before.hex.length >> 1 }} bytes{{ view.after ? ', readable' : '' }}</span>
          </button>
          <HexGrid
            v-if="beforeOpen" data-testid="inspector-before" :hex="view.before.hex" :id-prefix="beforeId" :lit-class="beforeLit" :marks="view.fieldsOn === 'before' ? marks : undefined"
            :selected="view.after ? null : ui.selectedByte" class="g-before" @pick="o => !view?.after && pick(o)"
          />
        </section>
        <div v-else-if="view.beforeHidden" class="grid-sec hidden-note" data-testid="inspector-before-hidden">
          <span class="gh-title">Before: hidden</span>
          <span class="muted">The eavesdropper has no key, so it never sees the readable bytes.</span>
        </div>
        <div v-if="(view.before || view.beforeHidden) && view.after" class="became" aria-hidden="true">{{ locked ? '▼ locked with the key, then sent' : '▼ sent' }}</div>
        <section v-if="view.after" class="grid-sec">
          <div class="grid-head static" :class="{ hl: !view.before && isHighlighted('inspector', 'toggle', 'wire-plain') }">
            <span class="gh-title">{{ view.before || view.beforeHidden ? 'After: what goes on the wire' : locked ? 'On the wire' : 'On the wire, readable: nothing locked it' }}</span>
            <span class="muted" data-testid="inspector-after-count">{{ afterLen }} bytes</span>
          </div>
          <HexGrid
            data-testid="inspector-after" :hex="view.after.hex" id-prefix="inspector-byte" :lit-class="afterLit" :marks="view.fieldsOn === 'after' ? marks : undefined"
            :selected="ui.selectedByte" :scramble="scramble" :class="['g-after', { 'g-locked': locked }]" :encrypted="hiddenAt" @pick="pick"
          />
        </section>
      </div>
      <div class="field-list" role="group" aria-label="Fields of this message">
        <div class="fl-hint muted">{{ fields.length ? 'Pick a field to light its bytes. Pick it again to turn it off.' : 'This message lists no fields.' }}</div>
        <div v-if="eve && unreadableBytes" class="field-row unreadable">unreadable without the key ({{ unreadableBytes }} bytes)</div>
        <template v-for="f in fields" :key="fieldKey(f)">
          <button
            v-if="readable(f)" type="button" class="field-row" :class="[`k-${f.kind}`, { on: isLit(f), hl: isHighlighted('inspector', 'field', f.name) }]"
            :aria-pressed="isLit(f)" :data-testid="`inspector-field-row-${f.name}`" @click="toggleField(fieldKey(f))"
          >
            <span class="fname"><i class="swatch" :class="`k-${f.kind}`" />{{ f.name }}</span>
            <span class="muted">{{ where(f) }}</span>
            <span v-if="f.gloss && f.gloss.toLowerCase() !== f.name.toLowerCase()" class="fgloss">{{ f.gloss }}</span>
            <span class="fval" :data-testid="`inspector-field-value-${f.name}`">{{ decoded(f) }}</span>
          </button>
        </template>
      </div>
    </div>
  </div>
</template>
