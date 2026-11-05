<script setup lang="ts">
import { computed } from 'vue'
import { chainOf, type Status } from '../lab'
import { allEvents, selectedEvent, selectEvent } from '../store'
import type { TraceEvent } from '../types'

// Lesson 4: three linked cards. Root, leaf, and the proof that the server holds the leaf's key. A link colors from the check events and from nothing else.
const upTo = computed(() => selectedEvent.value?.seq ?? Infinity)
const chain = computed(() => chainOf(allEvents.value, upTo.value))
const mark = (s: Status | undefined) => (s === 'fail' ? '✕' : s === 'pass' ? '✓' : '…')
const label = (s: Status | undefined) => (s === 'fail' ? 'failed' : s === 'pass' ? 'passed' : 'not checked yet')
const rows = (e: TraceEvent | null) => (e ? e.fields.slice(0, 8).map(f => ({ name: f.name, hex: e.plain.slice(f.offset * 2, (f.offset + Math.min(f.length, 12)) * 2), more: f.length > 12 })) : [])
const leafBadges = computed(() => ['validity window', 'name match'].map(n => ({ n, s: chain.value.checks[n] })))
</script>

<template>
  <div class="chain" data-testid="chain-panel">
    <div v-if="!chain.root && !chain.leaf" class="empty-note">The certificates appear here when the authority issues them.</div>
    <div v-else class="chain-row">
      <div class="chain-card" data-testid="chain-card-root" @click="chain.root && selectEvent(chain.root.seq)">
        <div class="side-title">ROOT</div>
        <div v-for="r in rows(chain.root)" :key="r.name" class="crow"><span>{{ r.name }}</span><code>{{ r.hex }}{{ r.more ? '…' : '' }}</code></div>
        <div v-if="!chain.root" class="muted">not issued yet</div>
      </div>
      <div class="chain-link" :class="chain.rootToLeaf" data-testid="chain-link-1" :data-status="chain.rootToLeaf" :title="`chain to trust anchor ${label(chain.checks['chain to trust anchor'])}, signature verify ${label(chain.checks['signature verify'])}`">
        <span class="lk">{{ mark(chain.rootToLeaf) }}</span><span class="muted">signed by</span>
      </div>
      <div class="chain-card" data-testid="chain-card-leaf" @click="chain.leaf && selectEvent(chain.leaf.seq)">
        <div class="side-title">SERVER CERTIFICATE</div>
        <div v-for="r in rows(chain.leaf)" :key="r.name" class="crow"><span>{{ r.name }}</span><code>{{ r.hex }}{{ r.more ? '…' : '' }}</code></div>
        <div v-if="!chain.leaf" class="muted">not issued yet</div>
        <div class="badges"><span v-for="b in leafBadges" :key="b.n" class="cb" :class="b.s ?? 'pending'" :data-testid="`chain-badge-${b.n}`">{{ mark(b.s) }} {{ b.n }}</span></div>
      </div>
      <div class="chain-link" :class="chain.leafToProof" data-testid="chain-link-2" :data-status="chain.leafToProof" :title="`CertificateVerify signature ${label(chain.checks['CertificateVerify signature'])}`">
        <span class="lk">{{ mark(chain.leafToProof) }}</span><span class="muted">proves key</span>
      </div>
      <div class="chain-card" data-testid="chain-card-proof" @click="chain.proof && selectEvent(chain.proof.seq)">
        <div class="side-title">PROOF (CertificateVerify)</div>
        <div v-if="chain.proof" class="crow"><span>sent</span><code>{{ chain.proof.plain.length >> 1 }} bytes</code></div>
        <div v-else class="muted">not sent yet</div>
      </div>
    </div>
  </div>
</template>
