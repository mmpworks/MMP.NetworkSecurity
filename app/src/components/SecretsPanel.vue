<script setup lang="ts">
import { computed, reactive } from 'vue'
import { isHighlighted, isReal, selectedEvent, shownEvents, ui, upToSeq } from '../store'

interface Row { holder: string; name: string; hex: string; derivedFrom: string[]; fresh: boolean }

const upTo = upToSeq
// A row exists only when the holder gained the value at or before the selected event.
const rows = computed<Row[]>(() => {
  const m = new Map<string, Row>()
  for (const e of shownEvents.value) {
    if (e.seq > upTo.value) break
    for (const s of e.secrets) m.set(`${s.holder.toLowerCase()}.${s.name}`, { holder: s.holder.toLowerCase(), name: s.name, hex: s.hex, derivedFrom: s.derivedFrom, fresh: e.seq === upTo.value })
  }
  return [...m.values()]
})
const eve = computed(() => ui.view === 'eavesdropper')
const holders = computed(() => [...new Set(rows.value.map(r => r.holder))])
const colsFor = (h: string) => rows.value.filter(r => r.holder === h)

// Public values an eavesdropper keeps: random numbers and key shares that travelled in the clear.
const publicValues = computed(() => {
  const out: { key: string; name: string; hex: string }[] = []
  for (const e of shownEvents.value) {
    if (e.seq > upTo.value) break
    if (e.type !== 'wire.sent') continue
    for (const f of e.fields) if (f.visibleToWire && (f.kind === 'random' || f.kind === 'key')) out.push({ key: `${e.seq}.${f.name}`, name: f.name, hex: e.wire.slice(f.offset * 2, (f.offset + Math.min(f.length, 16)) * 2) })
  }
  return out
})

// Convergence: a secret name that two holders both hold. The grids compare the two real values.
const pairs = computed(() => {
  const byName = new Map<string, Row[]>()
  for (const r of rows.value) byName.set(r.name, [...(byName.get(r.name) ?? []), r])
  return [...byName.entries()].filter(([, v]) => new Set(v.map(r => r.holder)).size >= 2).map(([name, v]) => ({ name, rows: v, match: v.every(r => r.hex === v[0].hex) }))
})
const cells = (hex: string) => Array.from({ length: Math.min(64, hex.length >> 1) }, (_, i) => hex.slice(i * 2, i * 2 + 2))

const open = reactive(new Set<string>())
const toggle = (k: string) => { if (open.has(k)) open.delete(k); else open.add(k) }
const short = (hex: string) => (hex.length > 24 ? `${hex.slice(0, 16)}…${hex.slice(-8)}` : hex)
const copy = (hex: string) => { try { void navigator.clipboard?.writeText(hex) } catch { /* clipboard may be blocked */ } }
</script>

<template>
  <div class="secrets" data-testid="secrets-panel">
    <div class="inspector-tools"><span class="side-title">WHAT EACH SIDE KNOWS</span></div>
    <div v-if="isReal" class="empty-note">Values are held by the OS. This course shows none of them with the OS transport.</div>
    <template v-else-if="eve">
      <div class="secret-cols">
        <div class="secret-col" data-testid="secrets-col-eavesdropper">
          <div class="col-head">Eavesdropper</div>
          <div v-if="!publicValues.length" class="empty-note">Nothing yet.</div>
          <div v-for="p in publicValues" :key="p.key" class="secret-row"><span class="sname">{{ p.name }}</span><code>{{ short(p.hex) }}</code></div>
        </div>
      </div>
    </template>
    <div v-else-if="!rows.length" class="empty-note">A value shows here when a side learns it.</div>
    <template v-else>
      <div class="secret-cols">
        <div v-for="h in holders" :key="h" class="secret-col" :data-testid="`secrets-col-${h}`">
          <div class="col-head">{{ h }}</div>
          <div
            v-for="r in colsFor(h)" :key="r.name" class="secret-row" :class="{ fresh: r.fresh, hl: isHighlighted('secrets', 'row', `${r.holder}.${r.name}`) }"
            :data-testid="`secret-row-${r.holder}-${r.name}`"
          >
            <span class="sname">{{ r.name }}</span>
            <code>{{ open.has(h + r.name) ? r.hex : short(r.hex) }}</code>
            <span class="muted">{{ r.hex.length >> 1 }} bytes</span>
            <span v-for="d in r.derivedFrom" :key="d" class="chip-from">{{ d }}</span>
            <v-btn size="x-small" variant="text" :data-testid="`secret-reveal-${r.holder}-${r.name}`" @click="toggle(h + r.name)">{{ open.has(h + r.name) ? 'Hide' : 'Show all' }}</v-btn>
            <v-btn size="x-small" variant="text" icon="mdi-content-copy" aria-label="Copy value" @click="copy(r.hex)" />
          </div>
        </div>
      </div>
      <div v-for="p in pairs" :key="p.name" class="converge" :class="{ match: p.match }">
        <div class="muted">{{ p.name }}: {{ p.match ? 'both sides hold the same value' : 'the values differ' }}</div>
        <div class="grids">
          <div v-for="r in p.rows" :key="r.holder" class="grid32" :data-testid="`convergence-grid-${r.holder}`">
            <span v-for="(c, i) in cells(r.hex)" :key="i" class="cell">{{ c }}</span>
          </div>
        </div>
        <div v-if="p.match" class="match-tag" data-testid="convergence-match">✓ match</div>
      </div>
    </template>
  </div>
</template>
