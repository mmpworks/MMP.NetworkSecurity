<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { ASCII, fieldAt, h2, hexToBytes, isProtected } from '../layout'
import { flipSelectedByte, isHighlighted, isReal, replayTick, selectedEvent, ui } from '../store'

const PER_ROW = 16
const ROW_H = 22

const ev = computed(() => selectedEvent.value)
const eve = computed(() => ui.view === 'eavesdropper')
// Endpoints read the bytes before protection; the eavesdropper reads the bytes on the wire (ux-design.md section 1.4).
const showPlain = computed(() => (ui.showPlain != null ? ui.showPlain : !eve.value) && !!ev.value?.plain)
const hex = computed(() => (ev.value ? (showPlain.value ? ev.value.plain : ev.value.wire) : ''))
const bytes = computed(() => hexToBytes(hex.value))
const fields = computed(() => (ev.value?.fields ?? []).filter(f => !eve.value || f.visibleToWire))
const hiddenField = (off: number) => eve.value && (ev.value?.fields ?? []).some(f => !f.visibleToWire && off >= f.offset && off < f.offset + f.length)
const unreadableBytes = computed(() => (eve.value ? (ev.value?.fields ?? []).filter(f => !f.visibleToWire).reduce((n, f) => n + f.length, 0) : 0))
const startOf = computed(() => new Map(fields.value.map(f => [f.offset, f.name])))

// ---- virtual rows ----
const scroller = ref<HTMLElement | null>(null)
const top = ref(0)
const height = ref(240)
const rowCount = computed(() => Math.ceil(bytes.value.length / PER_ROW))
const firstRow = computed(() => Math.max(0, Math.floor(top.value / ROW_H) - 2))
const lastRow = computed(() => Math.min(rowCount.value, Math.ceil((top.value + height.value) / ROW_H) + 2))
const rows = computed(() => Array.from({ length: Math.max(0, lastRow.value - firstRow.value) }, (_, i) => firstRow.value + i))
function onScroll() { top.value = scroller.value?.scrollTop ?? 0; height.value = scroller.value?.clientHeight ?? 240 }

// ---- the scramble: readable bytes turn into the ciphertext they became (moment 1) ----
const morph = ref(1)
const tick = ref(0)
let timer: ReturnType<typeof setInterval> | null = null
const reduced = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches
function playScramble() {
  if (timer) clearInterval(timer)
  morph.value = 1
  const e = ev.value
  if (reduced || !e || !isProtected(e) || showPlain.value || ui.viewUpTo !== null && ui.viewUpTo < 0) return
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
const scrambling = computed(() => morph.value < 1)
function shown(i: number): string {
  if (!scrambling.value || i / Math.max(1, bytes.value.length) < morph.value) return h2(bytes.value[i])
  return h2((i * 131 + tick.value * 17) & 0xff)
}

function kindOf(off: number): string {
  if (hiddenField(off)) return 'k-cipher'
  return `k-${fieldAt(fields.value, off)?.kind ?? 'none'}`
}
const hl = (off: number) => { const f = fieldAt(fields.value, off); return !!f && isHighlighted('inspector', 'field', f.name) }
const decoded = (f: { offset: number; length: number }) => { const h = hex.value.slice(f.offset * 2, (f.offset + Math.min(f.length, 12)) * 2); return f.length > 12 ? `${h}…` : h }
const pick = (off: number) => { ui.selectedByte = off }
const canFlip = computed(() => ui.selectedByte != null && !!ev.value && !isReal.value)
</script>

<template>
  <div class="inspector" data-testid="inspector">
    <div class="inspector-tools">
      <span class="side-title">BYTES</span>
      <span v-if="ev" class="muted">{{ ev.message || ev.type }} · {{ bytes.length }} bytes · {{ showPlain ? 'before protection' : 'on the wire' }}</span>
      <v-spacer />
      <v-btn v-if="ev?.plain" size="x-small" data-testid="inspector-toggle-wire-plain" @click="ui.showPlain = !showPlain">{{ showPlain ? 'Show wire' : 'Show plain' }}</v-btn>
      <v-btn size="x-small" color="error" :disabled="!canFlip" data-testid="flip-byte-button" @click="flipSelectedByte">Flip this byte</v-btn>
    </div>
    <div v-if="!ev || !bytes.length" class="empty-note">{{ ev ? 'This event moves no bytes.' : 'Bytes appear here when the engine sends a message.' }}</div>
    <div v-else class="inspector-body">
      <div ref="scroller" class="hex-scroll" @scroll="onScroll">
        <div class="hex-space" :style="{ height: rowCount * ROW_H + 'px' }">
          <div v-for="r in rows" :key="r" class="hex-row" :style="{ top: r * ROW_H + 'px' }">
            <span class="hex-off">{{ (r * PER_ROW).toString(16).padStart(4, '0') }}</span>
            <span class="hex-cells">
              <template v-for="i in Math.min(PER_ROW, bytes.length - r * PER_ROW)" :key="i">
                <i v-if="startOf.has(r * PER_ROW + i - 1)" class="span-mark" :data-testid="`inspector-span-${startOf.get(r * PER_ROW + i - 1)}`" />
                <span
                  class="hb" :class="[kindOf(r * PER_ROW + i - 1), { sel: ui.selectedByte === r * PER_ROW + i - 1, hl: hl(r * PER_ROW + i - 1), scr: scrambling }]"
                  :data-testid="`inspector-byte-${r * PER_ROW + i - 1}`" @click="pick(r * PER_ROW + i - 1)"
                >{{ shown(r * PER_ROW + i - 1) }}</span>
              </template>
            </span>
            <span class="hex-ascii">{{ bytes.slice(r * PER_ROW, r * PER_ROW + PER_ROW).map(ASCII).join('') }}</span>
          </div>
        </div>
      </div>
      <div class="field-list">
        <div v-if="eve && unreadableBytes" class="field-row unreadable">unreadable without the key ({{ unreadableBytes }} bytes)</div>
        <div v-for="f in fields" :key="f.name + f.offset" class="field-row" :class="[`k-${f.kind}`, { hl: isHighlighted('inspector', 'field', f.name) }]" :data-testid="`inspector-field-row-${f.name}`" :title="f.gloss" @click="pick(f.offset)">
          <span class="fname">{{ f.name }}</span>
          <span class="muted">{{ f.offset }} + {{ f.length }}</span>
          <span class="fval">{{ decoded(f) }}</span>
        </div>
      </div>
    </div>
  </div>
</template>
