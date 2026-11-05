<script setup lang="ts">
import { computed } from 'vue'
import { CLAIM_WORDS, isTimeClaim, jsonOfEvent, tokenParts } from '../lab'
import { allEvents, selectedEvent, upToSeq } from '../store'

// Lesson 10: a token split into header, claims and signature, with the claims in everyday words. Text comes from the wire bytes and from
// the `token claims` and `proof claims` measure events. Nothing here is invented.
const ev = computed(() => selectedEvent.value)
const token = computed(() => tokenParts(ev.value, 'token'))
const proof = computed(() => tokenParts(ev.value, 'proof'))
const shownClaims = computed(() => {
  const list = allEvents.value.filter(e => e.type === 'measure.result' && (e.message === 'token claims' || e.message === 'proof claims') && e.seq <= upToSeq.value)
  return list.map(e => ({ e, label: e.message, claims: jsonOfEvent<Record<string, unknown>>(e) }))
})
const when = (v: unknown) => (typeof v === 'number' ? new Date(v * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : String(v))
const show = (k: string, v: unknown) => (isTimeClaim(k) ? when(v) : typeof v === 'object' ? JSON.stringify(v) : String(v))
const pretty = (s: string | null) => { if (!s) return ''; try { return JSON.stringify(JSON.parse(s)) } catch { return s } }
</script>

<template>
  <div class="token" data-testid="token-panel">
    <div v-if="!token && !proof && !shownClaims.length" class="empty-note">Pick a message that carries a token to see its three parts.</div>
    <template v-for="view in [token, proof]" :key="view?.kind">
      <div v-if="view" class="tok" :data-testid="`token-${view.kind}`">
        <div class="side-title">{{ view.kind === 'token' ? 'TOKEN' : 'PROOF OF POSSESSION' }}</div>
        <div v-for="p in view.parts" :key="p.name" class="tpart" :class="`tp-${p.name}`" :data-testid="`token-${view.kind}-${p.name}`">
          <span class="tname">{{ p.name }}</span>
          <code v-if="p.decoded">{{ pretty(p.decoded) }}</code>
          <code v-else class="muted">{{ p.text.slice(0, 28) }}{{ p.text.length > 28 ? '…' : '' }} ({{ p.text.length }} characters)</code>
        </div>
      </div>
    </template>
    <div v-for="m in shownClaims" :key="m.e.seq" class="tok" :data-testid="`claims-${m.label.replace(' ', '-')}`">
      <div class="side-title">{{ m.label.toUpperCase() }} IN WORDS</div>
      <div v-if="!m.claims" class="muted">The claims text could not be read.</div>
      <div v-for="(v, k) in m.claims" :key="k" class="crow" :data-testid="`claim-${k}`"><span>{{ CLAIM_WORDS[k] ?? k }} <span class="muted">({{ k }})</span></span><code>{{ show(String(k), v) }}</code></div>
    </div>
  </div>
</template>
